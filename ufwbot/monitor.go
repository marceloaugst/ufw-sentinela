package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Monitor vigia a VPS (CPU, memória, disco, serviços, Docker, sites e certificados TLS) e avisa
// no Telegram quando algo passa do limite e quando volta ao normal. As leituras são campos de
// função para os testes trocarem por valores fixos.
type Monitor struct {
	enviar func(texto string) error
	agora  func() time.Time
	dormir func(time.Duration)

	intervalo  time.Duration
	sustentado int // amostras seguidas acima do limite antes de avisar (CPU/RAM/disco)
	limCPU     float64
	limMem     float64
	limDisco   float64
	discoPath  string
	servicos   []string // unidades do systemd
	tcp        []string // host:porta que precisam aceitar conexão
	urls       []string // endereços que precisam responder 2xx/3xx
	tlsHosts   []string // host[:porta] cujo certificado é conferido
	tlsDias    int
	docker     bool
	arqEstado  string // guarda boot_id e o último sinal de vida

	lerCPU      func() (ocioso, total uint64, err error)
	lerMem      func() (pct float64, usado, total uint64, err error)
	lerDisco    func(path string) (pct float64, usado, total uint64, err error)
	lerUptime   func() (time.Duration, error)
	lerBootID   func() string
	lerLoad     func() string
	servico     func(unidade string) estadoServico
	abrirTCP    func(addr string) error
	checarURL   func(url string) error
	certExpira  func(host string) (time.Time, error)
	containers  func() ([]container, error)
	cpuAnterior [2]uint64
	temCPU      bool
	ultimoTLS   time.Time

	mu      sync.Mutex // painel (laço do Telegram) x ciclo (rotina de fundo)
	estados map[string]*estadoAlerta
}

type estadoAlerta struct {
	falhas int
	ativo  bool
	ultimo time.Time
}

type estadoServico struct {
	Achado bool // false = a unidade não existe nesta máquina (ignorada)
	Ativo  bool
	Estado string
}

type container struct{ Nome, Estado, Status string }

// estadoArquivo é o que sobrevive entre execuções: detecta reinício da VPS e do próprio bot.
type estadoArquivo struct {
	BootID string    `json:"boot_id"`
	Sinal  time.Time `json:"sinal"`
}

// ---- configuração ----

// novoMonitor lê as variáveis MON_*. Devolve nil se MON_INTERVALO=0 (desligado).
func novoMonitor(b *Bot) (*Monitor, error) {
	if envOu("MON_INTERVALO", "30s") == "0" {
		return nil, nil
	}
	m := &Monitor{
		enviar: func(t string) error {
			return b.chamar("sendMessage", urlValues("chat_id", strconv.FormatInt(b.chatAutorizado, 10), "text", t), nil)
		},
		agora: time.Now, dormir: time.Sleep,
		discoPath: envOu("MON_DISCO_PATH", "/"),
		docker:    envOu("MON_DOCKER", "1") != "0",
		arqEstado: envOu("MON_ESTADO", "log/monitor.json"),
	}
	var err error
	if m.intervalo, err = parseDuracao(envOu("MON_INTERVALO", "30s")); err != nil {
		return nil, fmt.Errorf("MON_INTERVALO inválido: %w", err)
	}
	sust, err := parseDuracao(envOu("MON_SUSTENTADO", "2m"))
	if err != nil {
		return nil, fmt.Errorf("MON_SUSTENTADO inválido: %w", err)
	}
	m.sustentado = max(1, int(sust/m.intervalo))
	for _, l := range []struct {
		dest *float64
		nome string
		pad  string
	}{{&m.limCPU, "MON_CPU", "90"}, {&m.limMem, "MON_MEM", "90"}, {&m.limDisco, "MON_DISCO", "90"}} {
		if *l.dest, err = strconv.ParseFloat(envOu(l.nome, l.pad), 64); err != nil || *l.dest < 0 || *l.dest > 100 {
			return nil, fmt.Errorf("%s inválido (0 a 100; 0 desliga)", l.nome)
		}
	}
	if m.tlsDias, err = strconv.Atoi(envOu("MON_TLS_DIAS", "14")); err != nil || m.tlsDias < 0 {
		return nil, fmt.Errorf("MON_TLS_DIAS inválido")
	}
	m.servicos = lista(envOu("MON_SERVICOS", "postgresql,redis-server,redis,docker,nginx"))
	m.tcp = lista(envOu("MON_TCP", ""))
	m.urls = lista(envOu("MON_URLS", ""))
	m.tlsHosts = lista(envOu("MON_TLS", ""))
	m.usarSistema()
	return m, nil
}

func lista(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func urlValues(kv ...string) map[string][]string {
	v := map[string][]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		v[kv[i]] = []string{kv[i+1]}
	}
	return v
}

// usarSistema liga as leituras reais (Linux).
func (m *Monitor) usarSistema() {
	m.lerCPU = lerCPUProc
	m.lerMem = lerMemProc
	m.lerDisco = lerDiscoStatfs
	m.lerUptime = lerUptimeProc
	m.lerBootID = func() string {
		d, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
		return strings.TrimSpace(string(d))
	}
	m.lerLoad = func() string {
		d, _ := os.ReadFile("/proc/loadavg")
		f := strings.Fields(string(d))
		if len(f) < 3 {
			return ""
		}
		return strings.Join(f[:3], " ")
	}
	m.servico = servicoSystemd
	m.abrirTCP = func(addr string) error {
		c, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err == nil {
			c.Close()
		}
		return err
	}
	cli := &http.Client{Timeout: 10 * time.Second}
	m.checarURL = func(u string) error {
		resp, err := cli.Get(u)
		if err != nil {
			return fmt.Errorf("sem resposta")
		}
		resp.Body.Close()
		if resp.StatusCode >= 400 {
			return fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return nil
	}
	m.certExpira = certificadoExpira
	m.containers = containersDocker
}

// ---- leituras do sistema ----

func parseCPU(linha string) (ocioso, total uint64, err error) {
	f := strings.Fields(linha)
	if len(f) < 5 || f[0] != "cpu" {
		return 0, 0, fmt.Errorf("linha cpu inesperada")
	}
	for i, s := range f[1:min(len(f), 9)] { // guest já está contido em user/nice
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return 0, 0, err
		}
		total += n
		if i == 3 || i == 4 { // idle + iowait
			ocioso += n
		}
	}
	return ocioso, total, nil
}

func lerCPUProc() (uint64, uint64, error) {
	d, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	linha, _, _ := strings.Cut(string(d), "\n")
	return parseCPU(linha)
}

func parseMem(texto string) (pct float64, usado, total uint64, err error) {
	var disp uint64
	achou := 0
	for _, l := range strings.Split(texto, "\n") {
		nome, resto, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		f := strings.Fields(resto)
		if len(f) == 0 {
			continue
		}
		n, e := strconv.ParseUint(f[0], 10, 64)
		if e != nil {
			continue
		}
		switch nome {
		case "MemTotal":
			total, achou = n*1024, achou+1
		case "MemAvailable":
			disp, achou = n*1024, achou+1
		}
	}
	if achou < 2 || total == 0 {
		return 0, 0, 0, fmt.Errorf("meminfo incompleto")
	}
	usado = total - min(disp, total)
	return float64(usado) / float64(total) * 100, usado, total, nil
}

func lerMemProc() (float64, uint64, uint64, error) {
	d, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, 0, err
	}
	return parseMem(string(d))
}

func lerDiscoStatfs(path string) (float64, uint64, uint64, error) {
	var s syscall.Statfs_t
	if err := syscall.Statfs(path, &s); err != nil {
		return 0, 0, 0, err
	}
	bs := uint64(s.Bsize)
	usado := (s.Blocks - s.Bfree) * bs
	total := usado + s.Bavail*bs // mesma conta do df
	if total == 0 {
		return 0, 0, 0, fmt.Errorf("disco sem tamanho")
	}
	return float64(usado) / float64(total) * 100, usado, total, nil
}

func lerUptimeProc() (time.Duration, error) {
	d, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	s, _, _ := strings.Cut(string(d), " ")
	f, err := strconv.ParseFloat(s, 64)
	return time.Duration(f * float64(time.Second)), err
}

// servicoSystemd consulta o systemd sem shell. "not-found" = unidade inexistente.
func servicoSystemd(unidade string) estadoServico {
	out, _ := exec.Command("systemctl", "show", "-p", "LoadState", "-p", "ActiveState", "--", unidade).Output()
	return parseSystemd(string(out))
}

func parseSystemd(saida string) estadoServico {
	var load, ativo string
	for _, l := range strings.Split(saida, "\n") {
		if v, ok := strings.CutPrefix(l, "LoadState="); ok {
			load = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(l, "ActiveState="); ok {
			ativo = strings.TrimSpace(v)
		}
	}
	if load == "" || load == "not-found" {
		return estadoServico{}
	}
	return estadoServico{Achado: true, Ativo: ativo == "active", Estado: ativo}
}

func certificadoExpira(host string) (time.Time, error) {
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "443")
	}
	nome, _, _ := net.SplitHostPort(host)
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 8 * time.Second}, "tcp", host, &tls.Config{ServerName: nome})
	if err != nil {
		return time.Time{}, err
	}
	defer c.Close()
	certs := c.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return time.Time{}, fmt.Errorf("sem certificado")
	}
	return certs[0].NotAfter, nil
}

var reSaiu = regexp.MustCompile(`^Exited \((\d+)\)`)

func containersDocker() ([]container, error) {
	out, err := exec.Command("docker", "ps", "-a", "--format", "{{.Names}}|{{.State}}|{{.Status}}").Output()
	if err != nil {
		return nil, err
	}
	var cs []container
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if p := strings.SplitN(l, "|", 3); len(p) == 3 {
			cs = append(cs, container{p[0], p[1], p[2]})
		}
	}
	return cs, nil
}

// problemaContainer devolve o motivo de um container estar mal ("" se está bem).
// Container que terminou com código 0 é tarefa concluída, não falha.
func problemaContainer(c container) string {
	switch {
	case strings.Contains(c.Status, "(unhealthy)"):
		return "unhealthy"
	case c.Estado == "restarting", c.Estado == "dead":
		return c.Estado
	}
	if r := reSaiu.FindStringSubmatch(c.Status); r != nil && r[1] != "0" {
		return "saiu com código " + r[1]
	}
	return ""
}

// ---- alertas ----

// avaliar mantém o estado de um alerta: avisa depois de minFalhas ruins seguidas, avisa a
// volta ao normal, e repete o aviso a cada "lembrar" enquanto durar (0 = não repete).
func (m *Monitor) avaliar(chave string, ruim bool, msgRuim, msgOk string, minFalhas int, lembrar time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.avaliarLocked(chave, ruim, msgRuim, msgOk, minFalhas, lembrar)
}

func (m *Monitor) avaliarLocked(chave string, ruim bool, msgRuim, msgOk string, minFalhas int, lembrar time.Duration) {
	if m.estados == nil {
		m.estados = map[string]*estadoAlerta{}
	}
	s := m.estados[chave]
	if s == nil {
		s = &estadoAlerta{}
		m.estados[chave] = s
	}
	agora := m.agora()
	if ruim {
		s.falhas++
		switch {
		case !s.ativo && s.falhas >= minFalhas:
			s.ativo, s.ultimo = true, agora
			m.enviar(msgRuim)
		case s.ativo && lembrar > 0 && agora.Sub(s.ultimo) >= lembrar:
			s.ultimo = agora
			m.enviar(msgRuim)
		}
		return
	}
	s.falhas = 0
	if s.ativo {
		s.ativo = false
		if msgOk != "" {
			m.enviar(msgOk)
		}
	}
}

func (m *Monitor) ativo(chave string) bool {
	s := m.estados[chave]
	return s != nil && s.ativo
}

// acima compara com histerese: depois de alertar, só "volta ao normal" 5 pontos abaixo do limite.
func (m *Monitor) acima(chave string, valor, limite float64) bool {
	if limite <= 0 {
		return false
	}
	if m.ativo(chave) {
		return valor >= limite-5
	}
	return valor >= limite
}

// ciclo faz uma rodada de leituras e dispara os alertas que couberem.
func (m *Monitor) ciclo() {
	m.mu.Lock()
	defer m.mu.Unlock()
	host, _ := os.Hostname()

	if ocioso, total, err := m.lerCPU(); err == nil {
		if m.temCPU && total > m.cpuAnterior[1] {
			pct := 100 * (1 - float64(ocioso-m.cpuAnterior[0])/float64(total-m.cpuAnterior[1]))
			m.avaliarLocked("cpu", m.acima("cpu", pct, m.limCPU),
				fmt.Sprintf("🔥 CPU alta em %s: %.0f%% há mais de %s", host, pct, humano(time.Duration(m.sustentado)*m.intervalo)),
				fmt.Sprintf("✅ CPU normalizou em %s: %.0f%%", host, pct), m.sustentado, 0)
		}
		m.cpuAnterior, m.temCPU = [2]uint64{ocioso, total}, true
	}
	if pct, usado, total, err := m.lerMem(); err == nil {
		m.avaliarLocked("mem", m.acima("mem", pct, m.limMem),
			fmt.Sprintf("🧠 Memória alta em %s: %.0f%% (%s de %s)", host, pct, gb(usado), gb(total)),
			fmt.Sprintf("✅ Memória normalizou em %s: %.0f%%", host, pct), m.sustentado, 0)
	}
	if pct, usado, total, err := m.lerDisco(m.discoPath); err == nil {
		m.avaliarLocked("disco", m.acima("disco", pct, m.limDisco),
			fmt.Sprintf("💽 Disco %s quase cheio em %s: %.0f%% (%s de %s)", m.discoPath, host, pct, gb(usado), gb(total)),
			fmt.Sprintf("✅ Disco %s normalizou: %.0f%%", m.discoPath, pct), 1, 6*time.Hour)
	}
	for _, u := range m.servicos {
		s := m.servico(u)
		if !s.Achado {
			continue
		}
		m.avaliarLocked("svc:"+u, !s.Ativo,
			fmt.Sprintf("🔴 Serviço %s parou em %s (estado: %s)", u, host, s.Estado),
			fmt.Sprintf("✅ Serviço %s voltou em %s", u, host), 2, time.Hour)
	}
	for _, a := range m.tcp {
		err := m.abrirTCP(a)
		m.avaliarLocked("tcp:"+a, err != nil,
			fmt.Sprintf("🔴 %s não aceita conexões", a), fmt.Sprintf("✅ %s voltou a responder", a), 2, time.Hour)
	}
	for _, u := range m.urls {
		err := m.checarURL(u)
		motivo := ""
		if err != nil {
			motivo = err.Error()
		}
		m.avaliarLocked("url:"+u, err != nil,
			fmt.Sprintf("🔴 %s fora do ar (%s)", u, motivo), fmt.Sprintf("✅ %s voltou ao ar", u), 2, time.Hour)
	}
	if m.docker {
		m.cicloDocker(host)
	}
	if m.agora().Sub(m.ultimoTLS) >= time.Hour {
		m.ultimoTLS = m.agora()
		m.cicloTLS()
	}
	m.gravarSinal()
}

func (m *Monitor) cicloDocker(host string) {
	cs, err := m.containers()
	if err != nil {
		return // docker parado: o alerta do serviço "docker" cobre
	}
	visto := map[string]bool{}
	for _, c := range cs {
		chave := "docker:" + c.Nome
		visto[chave] = true
		p := problemaContainer(c)
		m.avaliarLocked(chave, p != "",
			fmt.Sprintf("🐳 Container %s com problema em %s: %s", c.Nome, host, p),
			fmt.Sprintf("✅ Container %s voltou ao normal", c.Nome), 2, time.Hour)
	}
	for k, s := range m.estados {
		if strings.HasPrefix(k, "docker:") && !visto[k] && s.ativo {
			m.avaliarLocked(k, false, "", "✅ Container "+strings.TrimPrefix(k, "docker:")+" não existe mais (alerta encerrado)", 1, 0)
		}
	}
}

type resultadoTLS struct {
	Host   string
	Expira time.Time
	Err    error
}

// verificarTLS consulta todos os hosts em paralelo.
func (m *Monitor) verificarTLS() []resultadoTLS {
	res := make([]resultadoTLS, len(m.tlsHosts))
	var wg sync.WaitGroup
	for i, h := range m.tlsHosts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t, err := m.certExpira(h)
			res[i] = resultadoTLS{h, t, err}
		}()
	}
	wg.Wait()
	return res
}

func (m *Monitor) cicloTLS() {
	for _, r := range m.verificarTLS() {
		chave := "tls:" + r.Host
		switch {
		case r.Err != nil:
			m.avaliarLocked(chave, true, fmt.Sprintf("🔐 Certificado de %s inválido ou inacessível: %v", r.Host, r.Err),
				"", 1, 24*time.Hour)
		default:
			dias := int(r.Expira.Sub(m.agora()).Hours() / 24)
			m.avaliarLocked(chave, m.tlsDias > 0 && dias <= m.tlsDias,
				fmt.Sprintf("🔐 Certificado de %s expira em %d dia(s) (%s)", r.Host, dias, r.Expira.Local().Format("02/01/2006")),
				fmt.Sprintf("✅ Certificado de %s renovado (vence em %d dias)", r.Host, dias), 1, 24*time.Hour)
		}
	}
}

// ---- reinícios ----

func (m *Monitor) lerSinal() (estadoArquivo, bool) {
	var e estadoArquivo
	d, err := os.ReadFile(m.arqEstado)
	if err != nil || json.Unmarshal(d, &e) != nil {
		return e, false
	}
	return e, true
}

func (m *Monitor) gravarSinal() {
	if m.arqEstado == "" {
		return
	}
	d, _ := json.Marshal(estadoArquivo{BootID: m.lerBootID(), Sinal: m.agora()})
	tmp := m.arqEstado + ".tmp"
	if err := os.WriteFile(tmp, d, 0o600); err == nil {
		err = os.Rename(tmp, m.arqEstado)
	}
}

// avisoDeInicio compara com o último sinal gravado: boot_id diferente = a VPS reiniciou;
// mesmo boot_id mas sem sinal por um tempo = só o bot foi reiniciado (deploy, crash).
func (m *Monitor) avisoDeInicio() string {
	ant, ok := m.lerSinal()
	if !ok || m.arqEstado == "" {
		return ""
	}
	host, _ := os.Hostname()
	fora := m.agora().Sub(ant.Sinal)
	up, _ := m.lerUptime()
	switch {
	case m.lerBootID() != "" && ant.BootID != m.lerBootID():
		return fmt.Sprintf("🔄 %s reiniciou. Sem sinal por %s (último às %s). Uptime atual: %s.",
			host, humano(fora), ant.Sinal.Local().Format("02/01 15:04"), humano(up))
	case fora > 3*m.intervalo:
		return fmt.Sprintf("♻️ Monitor reiniciado em %s (sem sinal por %s). A VPS segue ligada há %s.", host, humano(fora), humano(up))
	}
	return ""
}

func (m *Monitor) iniciar() {
	aviso := m.avisoDeInicio()
	m.gravarSinal()
	if aviso == "" {
		return
	}
	// logo após o boot a rede pode ainda não estar de pé: tenta por alguns minutos.
	for i := 0; i < 12; i++ {
		if err := m.enviar(aviso); err == nil {
			return
		}
		m.dormir(10 * time.Second)
	}
	log.Println("não consegui enviar o aviso de reinício")
}

func (m *Monitor) rodar() {
	m.iniciar()
	m.mu.Lock()
	if o, t, err := m.lerCPU(); err == nil {
		m.cpuAnterior, m.temCPU = [2]uint64{o, t}, true
	}
	m.mu.Unlock()
	log.Printf("monitor ligado (a cada %s; serviços: %s)", m.intervalo, strings.Join(m.servicos, ","))
	for range time.Tick(m.intervalo) {
		m.ciclo()
	}
}

// ---- painel ----

func (m *Monitor) painel() string {
	host, _ := os.Hostname()
	var l []string
	l = append(l, "🖥️ "+host)
	if up, err := m.lerUptime(); err == nil {
		l = append(l, "⏱️ Uptime: "+humano(up))
	}
	// CPU: duas leituras com uma pausa curta (o /proc/stat só acumula).
	o1, t1, e1 := m.lerCPU()
	m.dormir(500 * time.Millisecond)
	o2, t2, e2 := m.lerCPU()
	if e1 == nil && e2 == nil && t2 > t1 {
		pct := 100 * (1 - float64(o2-o1)/float64(t2-t1))
		l = append(l, fmt.Sprintf("%s CPU: %.0f%%  (load %s)", marca(pct, m.limCPU), pct, m.lerLoad()))
	}
	if pct, u, t, err := m.lerMem(); err == nil {
		l = append(l, fmt.Sprintf("%s RAM: %.0f%% (%s de %s)", marca(pct, m.limMem), pct, gb(u), gb(t)))
	}
	if pct, u, t, err := m.lerDisco(m.discoPath); err == nil {
		l = append(l, fmt.Sprintf("%s Disco %s: %.0f%% (%s de %s)", marca(pct, m.limDisco), m.discoPath, pct, gb(u), gb(t)))
	}
	var svc []string
	for _, u := range m.servicos {
		if s := m.servico(u); s.Achado {
			ic := "✅"
			if !s.Ativo {
				ic = "🔴"
			}
			svc = append(svc, ic+" "+u)
		}
	}
	if len(svc) > 0 {
		l = append(l, "", "Serviços: "+strings.Join(svc, "  "))
	}
	if m.docker {
		if cs, err := m.containers(); err == nil {
			ruins := 0
			for _, c := range cs {
				if problemaContainer(c) != "" {
					ruins++
					l = append(l, fmt.Sprintf("🐳 🔴 %s: %s", c.Nome, problemaContainer(c)))
				}
			}
			l = append(l, fmt.Sprintf("🐳 Containers: %d (%d com problema)", len(cs), ruins))
		}
	}
	for _, a := range m.tcp {
		ic := "✅"
		if m.abrirTCP(a) != nil {
			ic = "🔴"
		}
		l = append(l, ic+" "+a)
	}
	for _, u := range m.urls {
		ic := "✅"
		if m.checarURL(u) != nil {
			ic = "🔴"
		}
		l = append(l, ic+" "+u)
	}
	if rs := m.verificarTLS(); len(rs) > 0 {
		sort.Slice(rs, func(i, j int) bool { return rs[i].Host < rs[j].Host })
		l = append(l, "")
		for _, r := range rs {
			if r.Err != nil {
				l = append(l, "🔐 🔴 "+r.Host+": "+r.Err.Error())
				continue
			}
			dias := int(r.Expira.Sub(m.agora()).Hours() / 24)
			ic := "✅"
			if m.tlsDias > 0 && dias <= m.tlsDias {
				ic = "⚠️"
			}
			l = append(l, fmt.Sprintf("🔐 %s %s: %d dias", ic, r.Host, dias))
		}
	}
	l = append(l, "", "Atualizado às "+m.agora().Local().Format("15:04:05"))
	return strings.Join(l, "\n")
}

func marca(valor, limite float64) string {
	switch {
	case limite > 0 && valor >= limite:
		return "🔴"
	case limite > 0 && valor >= limite-10:
		return "🟡"
	}
	return "🟢"
}

func gb(b uint64) string { return fmt.Sprintf("%.1f GB", float64(b)/(1<<30)) }

func humano(d time.Duration) string {
	d = d.Round(time.Second)
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%dd %dh", d/(24*time.Hour), d%(24*time.Hour)/time.Hour)
	case d >= time.Hour:
		return fmt.Sprintf("%dh %dm", d/time.Hour, d%time.Hour/time.Minute)
	case d >= time.Minute:
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return fmt.Sprintf("%ds", d/time.Second)
}
