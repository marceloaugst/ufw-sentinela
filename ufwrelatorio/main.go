package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/xuri/excelize/v2"
)

const formatoData = "02/01/2006 15:04"

// Padrões das linhas que nos interessam.
var (
	reBan      = regexp.MustCompile(`\[(\S+)\]\s+Ban\s+(\S+)`)
	reUnban    = regexp.MustCompile(`\[(\S+)\]\s+Unban\s+(\S+)`)
	reFalha    = regexp.MustCompile(`Failed \S+ for (?:invalid user )?(\S+) from (\S+)`)
	reInvalido = regexp.MustCompile(`[Ii]nvalid user (\S*) from (\S+)`)
)

func main() {
	hoje := flag.Bool("hoje", false, "só os eventos de hoje")
	de := flag.String("de", "", "data inicial, DD/MM/AAAA (inclusive)")
	ate := flag.String("ate", "", "data final, DD/MM/AAAA (inclusive)")
	semGeo := flag.Bool("semgeo", false, "não consulta país/ASN/abuso dos IPs")
	limite := flag.Int("limite", 10, "tentativas por IP a partir das quais ele deve ser banido")
	flag.Parse()

	filtro, err := novoFiltro(*hoje, *de, *ate)
	if err != nil {
		log.Fatal(err)
	}

	ufwLog, f2bLog, authLog := "/var/log/ufw.log", "/var/log/fail2ban.log", "/var/log/auth.log"
	if a := flag.Args(); len(a) == 3 {
		ufwLog, f2bLog, authLog = a[0], a[1], a[2]
	}
	if filtro.ativo() {
		fmt.Println("Período:", filtro)
	}

	f := excelize.NewFile()
	defer f.Close()
	estilos, err := criarEstilos(f)
	if err != nil {
		log.Fatal(err)
	}

	linhasUfw, avisoUfw := abaUfw(ufwLog, filtro)
	linhasBan, avisoBan := abaBanidos(f2bLog, filtro)
	// O status de banimento usa o histórico COMPLETO do fail2ban, sem o filtro de datas:
	// um IP banido ontem continua banido hoje.
	historico, errHist := coletarBans(f2bLog, Filtro{})
	if errHist != nil {
		avisoBan = errHist.Error()
	}
	// Bans feitos pelo ufwbot (regra "deny from" no ufw) não aparecem no log do fail2ban.
	if historico == nil {
		historico = map[string]*InfoBan{}
	}
	if saida, err := exec.Command("ufw", "status").Output(); err != nil {
		fmt.Println("  aviso: não consegui ler o ufw status; IPs banidos pelo bot podem aparecer como pendentes:", err)
	} else {
		mesclarBansUfw(historico, string(saida))
	}
	linhasUsr, avisoUsr := abaUsuarios(authLog, filtro, historico)

	linhasSem, avisoSem := abaBloqueadosSemBan(ufwLog, filtro, historico, avisoBan)
	linhasLim, pendentes, perto := abaLimite(ufwLog, filtro, historico, linhasUsr, *limite)

	// País/ASN (ip-api.com) e, com ABUSEIPDB_KEY, nota de abuso. Falhas de rede não impedem o relatório.
	var geo *Geo
	if !*semGeo {
		geo = novoGeo(arquivoGeo, envOu("GEO_API", "http://ip-api.com"),
			envOu("ABUSEIPDB_API", "https://api.abuseipdb.com"), os.Getenv("ABUSEIPDB_KEY"))
		var todos, prioritarios []string
		prioritarios = append(prioritarios, pendentes...)
		for _, l := range linhasLim {
			prioritarios = append(prioritarios, l[0].(string))
		}
		for _, linhas := range []struct {
			l   [][]any
			col int
		}{{linhasBan, 0}, {linhasSem, 0}, {linhasLim, 0}, {linhasUsr, 1}} {
			for _, l := range linhas.l {
				todos = append(todos, l[linhas.col].(string))
			}
		}
		// Os IPs das abas vêm primeiro; os do log bruto (para o gráfico por país) completam o limite de consultas.
		todos = append(todos, pendentes...)
		for _, l := range linhasUfw {
			if ip, ok := l[3].(string); ok && ip != "" {
				todos = append(todos, ip)
			}
		}
		geo.Resolver(todos, prioritarios)
	}

	abas := []Aba{
		{"Log UFW", []string{"Data", "Ação", "Entrada", "Origem", "Destino", "Proto", "Porta origem", "Porta destino", "Linha original"},
			[]float64{17, 8, 10, 40, 40, 8, 13, 14, 120}, linhasUfw, avisoUfw},
		{"IPs Banidos", []string{"IP", "Jail", "Qtd. bans", "Último ban", "Último unban"},
			[]float64{40, 14, 11, 17, 17}, linhasBan, avisoBan},
		{"Bloqueados sem ban", []string{"IP", "Bloqueios", "Portas distintas", "Portas mais atingidas", "Primeiro bloqueio", "Último bloqueio"},
			[]float64{40, 11, 16, 40, 17, 17}, linhasSem, avisoSem},
		{"Perto do limite", []string{"IP", "Tentativas SSH", "Bloqueios UFW", "Maior contagem", "% do limite", "Situação"},
			[]float64{40, 15, 14, 15, 12, 30}, linhasLim, ""},
		{"Usuários", []string{"Usuário", "IP", "Tentativas", "Usuário existe?", "Última tentativa", "IP banido?"},
			[]float64{28, 40, 11, 16, 17, 30}, linhasUsr, avisoUsr},
	}

	enriquecerAbas(abas, colunaIP, geo)

	// A aba padrão "Sheet1" vira a primeira aba.
	f.SetSheetName("Sheet1", abas[0].nome)
	for i, a := range abas {
		if i > 0 {
			if _, err := f.NewSheet(a.nome); err != nil {
				log.Fatal(err)
			}
		}
		if err := escreverAba(f, a.nome, a.cab, a.larg, a.linhas, estilos); err != nil {
			log.Fatal(err)
		}
		status := fmt.Sprintf("%d linhas", len(a.linhas))
		if a.aviso != "" {
			status += " — AVISO: " + a.aviso
		}
		fmt.Printf("  %-12s %s\n", a.nome, status)
	}

	if err := os.MkdirAll("log", 0o755); err != nil {
		log.Fatal(err)
	}
	destino := filepath.Join("log", time.Now().Format("ufw_relatorio_2006-01-02_15-04-05.xlsx"))
	if err := f.SaveAs(destino); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Relatório salvo em", destino)

	carimbo := time.Now().Format("2006-01-02_15-04-05")
	graficos, err := gerarGraficos("log", carimbo, filtro.descricao(), linhasUfw, geo)
	if err != nil {
		fmt.Println("  aviso: não consegui gerar os gráficos:", err)
	}
	for _, g := range graficos {
		fmt.Println("Gráfico salvo em", g)
	}

	// Envio opcional ao Telegram: só acontece se as duas variáveis de ambiente existirem.
	token, chat := os.Getenv("TELEGRAM_TOKEN"), os.Getenv("TELEGRAM_CHAT_ID")
	if token != "" && chat != "" {
		legenda := fmt.Sprintf("Relatório UFW — %s\nPeríodo: %s\nEventos UFW: %d | IPs banidos: %d | Usuários: %d\nIPs bloqueados sem ban: %d\nLimite: %d tentativas | no limite sem ban: %d | perto do limite: %d",
			time.Now().Format("02/01/2006 15:04"), filtro.descricao(), len(linhasUfw), len(linhasBan), len(linhasUsr), len(linhasSem), *limite, len(pendentes), perto)
		var listaPend, botoes string
		if len(pendentes) > 0 {
			id, err := salvarPendentes(pendentes)
			if err != nil {
				log.Fatalf("erro ao salvar pendentes: %v", err)
			}
			listaPend = textoPendentes(pendentes, geo) // vai numa mensagem à parte: a legenda do arquivo só aceita 1024 caracteres
			botoes = tecladoBan(id)
		}
		api := os.Getenv("TELEGRAM_API")
		if api == "" {
			api = "https://api.telegram.org"
		}
		if err := enviarTelegram(api, token, chat, destino, legenda, ""); err != nil {
			log.Fatalf("erro ao enviar para o Telegram: %v", err)
		}
		for _, g := range graficos {
			if err := enviarFoto(api, token, chat, g, ""); err != nil {
				fmt.Println("  aviso: gráfico não enviado:", err)
			}
		}
		if listaPend != "" {
			if err := enviarMensagem(api, token, chat, listaPend, botoes); err != nil {
				log.Fatalf("erro ao enviar a lista de pendentes: %v", err)
			}
		}
		fmt.Println("Enviado ao Telegram.")
	}
}

// colunaIP diz em que coluna de cada aba está o IP (as outras abas não são enriquecidas).
var colunaIP = map[string]int{"IPs Banidos": 0, "Bloqueados sem ban": 0, "Perto do limite": 0, "Usuários": 1}

func envOu(k, padrao string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return padrao
}

// Aba descreve uma aba da planilha.
type Aba struct {
	nome   string
	cab    []string
	larg   []float64
	linhas [][]any
	aviso  string // preenchido se o log não pôde ser lido
}

// ---------- Aba 1: log do UFW ----------

func abaUfw(caminho string, flt Filtro) ([][]any, string) {
	linhas, err := lerLinhas(caminho)
	if err != nil {
		return nil, err.Error()
	}
	var out [][]any
	for _, l := range linhas {
		i := strings.Index(l, "[UFW ")
		fim := strings.Index(l[max(i, 0):], "]")
		if i < 0 || fim < 0 {
			continue
		}
		if !flt.passa(l) {
			continue
		}
		acao := strings.TrimPrefix(l[i+1:i+fim], "UFW ")
		c := map[string]string{}
		for _, par := range strings.Fields(l[i+fim+1:]) {
			if k, v, ok := strings.Cut(par, "="); ok {
				c[k] = v
			}
		}
		out = append(out, []any{valorTempo(l), acao, c["IN"], c["SRC"], c["DST"], c["PROTO"], c["SPT"], c["DPT"], l})
	}
	inverter(out) // mais recente primeiro
	return out, ""
}

// ---------- Aba 2: IPs banidos pelo fail2ban ----------

// InfoBan resume o histórico de um IP no fail2ban.
type InfoBan struct {
	jail         string
	bans         int
	ultBan, ultU time.Time
}

// banido: o último evento do IP foi um ban (não houve unban depois).
func (x *InfoBan) banido() bool { return !x.ultBan.IsZero() && !x.ultU.After(x.ultBan) }

// coletarBans lê o log do fail2ban e agrupa o histórico por IP, só com eventos dentro do filtro.
func coletarBans(caminho string, flt Filtro) (map[string]*InfoBan, error) {
	linhas, err := lerLinhas(caminho)
	if err != nil {
		return nil, err
	}
	ips := map[string]*InfoBan{}
	get := func(ip, jail string) *InfoBan {
		if ips[ip] == nil {
			ips[ip] = &InfoBan{jail: jail}
		}
		return ips[ip]
	}
	for _, l := range linhas {
		if !flt.passa(l) {
			continue
		}
		t, _ := parseTempo(l)
		if m := reBan.FindStringSubmatch(l); m != nil {
			x := get(m[2], m[1])
			x.bans++
			x.jail = m[1]
			if t.After(x.ultBan) {
				x.ultBan = t
			}
		} else if m := reUnban.FindStringSubmatch(l); m != nil {
			x := get(m[2], m[1])
			if t.After(x.ultU) {
				x.ultU = t
			}
		}
	}
	return ips, nil
}

func abaBanidos(caminho string, flt Filtro) ([][]any, string) {
	ips, err := coletarBans(caminho, flt)
	if err != nil {
		return nil, err.Error()
	}
	var out [][]any
	for ip, x := range ips {
		out = append(out, []any{ip, x.jail, x.bans, tempoOuVazio(x.ultBan), tempoOuVazio(x.ultU)})
	}
	// Mais recentemente banido primeiro.
	sort.Slice(out, func(i, j int) bool {
		a, _ := out[i][3].(time.Time)
		b, _ := out[j][3].(time.Time)
		if !a.Equal(b) {
			return a.After(b)
		}
		return out[i][0].(string) < out[j][0].(string)
	})
	return out, ""
}

// ---------- Aba: IPs bloqueados pelo UFW que nunca foram banidos ----------

// abaBloqueadosSemBan lista os IPs com eventos BLOCK no UFW que não aparecem como banidos
// no fail2ban, do que mais bloqueou para o que menos bloqueou.
func abaBloqueadosSemBan(caminho string, flt Filtro, bans map[string]*InfoBan, avisoBan string) ([][]any, string) {
	if avisoBan != "" { // sem o log do fail2ban não dá para afirmar quem foi banido
		return nil, "não foi possível ler o fail2ban: " + avisoBan
	}
	linhas, err := lerLinhas(caminho)
	if err != nil {
		return nil, err.Error()
	}
	type info struct {
		n             int
		portas        map[string]int
		primeiro, ult time.Time
	}
	ips := map[string]*info{}
	for _, l := range linhas {
		if !strings.Contains(l, "[UFW BLOCK]") || !flt.passa(l) {
			continue
		}
		c := map[string]string{}
		for _, par := range strings.Fields(l) {
			if k, v, ok := strings.Cut(par, "="); ok {
				c[k] = v
			}
		}
		ip := c["SRC"]
		if ip == "" || (bans[ip] != nil && bans[ip].bans > 0) {
			continue
		}
		x := ips[ip]
		if x == nil {
			x = &info{portas: map[string]int{}}
			ips[ip] = x
		}
		x.n++
		x.portas[c["PROTO"]+"/"+c["DPT"]]++
		if t, ok := parseTempo(l); ok {
			if x.primeiro.IsZero() || t.Before(x.primeiro) {
				x.primeiro = t
			}
			if t.After(x.ult) {
				x.ult = t
			}
		}
	}
	var out [][]any
	for ip, x := range ips {
		var top []string
		for _, kv := range topoMapa(x.portas, 3) {
			top = append(top, fmt.Sprintf("%s (%d)", kv.k, kv.v))
		}
		out = append(out, []any{ip, x.n, len(x.portas), strings.Join(top, ", "), tempoOuVazio(x.primeiro), tempoOuVazio(x.ult)})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i][1].(int), out[j][1].(int)
		if a != b {
			return a > b
		}
		return out[i][0].(string) < out[j][0].(string)
	})
	return out, ""
}

type parKV struct {
	k string
	v int
}

// topoMapa devolve os n itens de maior valor do mapa.
func topoMapa(m map[string]int, n int) []parKV {
	var l []parKV
	for k, v := range m {
		l = append(l, parKV{k, v})
	}
	sort.Slice(l, func(i, j int) bool {
		if l[i].v != l[j].v {
			return l[i].v > l[j].v
		}
		return l[i].k < l[j].k
	})
	if len(l) > n {
		l = l[:n]
	}
	return l
}

// ---------- Aba 3: usuários que tentaram acessar (SSH) ----------

func abaUsuarios(caminho string, flt Filtro, bans map[string]*InfoBan) ([][]any, string) {
	linhas, err := lerLinhas(caminho)
	if err != nil {
		return nil, err.Error()
	}
	type chave struct{ user, ip string }
	type info struct {
		falhas, invalidos int
		existe            bool
		ultima            time.Time
	}
	mapa := map[chave]*info{}
	get := func(k chave) *info {
		if mapa[k] == nil {
			mapa[k] = &info{existe: true}
		}
		return mapa[k]
	}
	for _, l := range linhas {
		if !flt.passa(l) {
			continue
		}
		t, _ := parseTempo(l)
		var k chave
		if m := reFalha.FindStringSubmatch(l); m != nil {
			k = chave{m[1], m[2]}
			x := get(k)
			x.falhas++
			if strings.Contains(l, "invalid user") {
				x.existe = false
			}
			if t.After(x.ultima) {
				x.ultima = t
			}
		} else if m := reInvalido.FindStringSubmatch(l); m != nil {
			k = chave{m[1], m[2]}
			x := get(k)
			x.invalidos++
			x.existe = false
			if t.After(x.ultima) {
				x.ultima = t
			}
		}
	}
	var out [][]any
	for k, x := range mapa {
		existe := "Sim"
		if !x.existe {
			existe = "Não"
		}
		out = append(out, []any{k.user, k.ip, max(x.falhas, x.invalidos), existe, tempoOuVazio(x.ultima), statusBan(bans[k.ip])})
	}
	// Mais tentativas primeiro.
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i][2].(int), out[j][2].(int)
		if a != b {
			return a > b
		}
		return out[i][0].(string)+out[i][1].(string) < out[j][0].(string)+out[j][1].(string)
	})
	return out, ""
}

// statusBan traduz o histórico do IP no fail2ban para um texto curto.
func statusBan(x *InfoBan) string {
	switch {
	case x == nil || x.bans == 0:
		return "Não"
	case x.banido():
		return fmt.Sprintf("Sim, banido agora (%dx)", x.bans)
	default:
		return fmt.Sprintf("Já foi banido (%dx), liberado", x.bans)
	}
}

// ---------- Utilidades ----------

// lerLinhas lê o arquivo e, se existir, o rotacionado ".1" (mais antigo vem antes).
// Os .gz não são lidos.
func lerLinhas(caminho string) ([]string, error) {
	var todas []string
	for _, c := range []string{caminho + ".1", caminho} {
		f, err := os.Open(c)
		if err != nil {
			if c == caminho {
				return nil, fmt.Errorf("%v (rode com sudo)", err)
			}
			continue // o ".1" é opcional
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1024*1024), 1024*1024)
		for sc.Scan() {
			todas = append(todas, sc.Text())
		}
		f.Close()
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	return todas, nil
}

// parseTempo lê o timestamp do início da linha. Formatos aceitos:
// ISO (2026-10-16T13:52:03-03:00), fail2ban (2026-10-16 13:52:03,123)
// e syslog clássico (Oct 16 13:52:03, sem ano: assume o ano atual).
func parseTempo(linha string) (time.Time, bool) {
	c := strings.Fields(linha)
	if len(c) == 0 {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339Nano, c[0]); err == nil {
		return t, true
	}
	if len(c) >= 2 {
		if t, err := time.ParseInLocation("2006-01-02 15:04:05,000", c[0]+" "+c[1], time.Local); err == nil {
			return t, true
		}
	}
	if len(c) >= 3 {
		agora := time.Now()
		t, err := time.ParseInLocation("Jan 2 15:04:05 2006", strings.Join(c[:3], " ")+fmt.Sprint(" ", agora.Year()), time.Local)
		if err == nil {
			if t.After(agora) {
				t = t.AddDate(-1, 0, 0)
			}
			return t, true
		}
	}
	return time.Time{}, false
}

func valorTempo(linha string) any {
	if t, ok := parseTempo(linha); ok {
		return t
	}
	return ""
}

func tempoOuVazio(t time.Time) any {
	if t.IsZero() {
		return ""
	}
	return t
}

func inverter(s [][]any) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

type estilos struct{ cabecalho, data, pct int }

func criarEstilos(f *excelize.File) (estilos, error) {
	cab, err := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Color: "FFFFFF"},
		Fill: excelize.Fill{Type: "pattern", Pattern: 1, Color: []string{"305496"}},
	})
	if err != nil {
		return estilos{}, err
	}
	fmtData := "dd/mm/yyyy hh:mm"
	dt, err := f.NewStyle(&excelize.Style{CustomNumFmt: &fmtData})
	if err != nil {
		return estilos{}, err
	}
	pct, err := f.NewStyle(&excelize.Style{NumFmt: 9}) // 9 = 0%
	return estilos{cab, dt, pct}, err
}

// escreverAba grava cabeçalho + linhas usando o StreamWriter (rápido para arquivos grandes).
func escreverAba(f *excelize.File, aba string, cab []string, larg []float64, linhas [][]any, e estilos) error {
	sw, err := f.NewStreamWriter(aba)
	if err != nil {
		return err
	}
	for i, w := range larg {
		if err := sw.SetColWidth(i+1, i+1, w); err != nil {
			return err
		}
	}
	h := make([]any, len(cab))
	for i, c := range cab {
		h[i] = excelize.Cell{StyleID: e.cabecalho, Value: c}
	}
	if err := sw.SetRow("A1", h); err != nil {
		return err
	}
	for i, l := range linhas {
		row := make([]any, len(l))
		for j, v := range l {
			if t, ok := v.(time.Time); ok {
				row[j] = excelize.Cell{StyleID: e.data, Value: t}
			} else if p, ok := v.(float64); ok {
				row[j] = excelize.Cell{StyleID: e.pct, Value: p}
			} else {
				row[j] = v
			}
		}
		cel, _ := excelize.CoordinatesToCellName(1, i+2)
		if err := sw.SetRow(cel, row); err != nil {
			return err
		}
	}
	if err := sw.Flush(); err != nil {
		return err
	}
	if len(linhas) > 0 {
		fim, _ := excelize.CoordinatesToCellName(len(cab), len(linhas)+1)
		return f.AutoFilter(aba, "A1:"+fim, nil)
	}
	return nil
}

// Filtro limita os eventos a um período. Datas vazias significam "sem limite".
type Filtro struct{ de, ate time.Time } // ate é exclusivo (início do dia seguinte)

func novoFiltro(hoje bool, de, ate string) (Filtro, error) {
	var f Filtro
	if hoje {
		d := time.Now()
		f.de = time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, time.Local)
		f.ate = f.de.AddDate(0, 0, 1)
		return f, nil
	}
	var err error
	if de != "" {
		if f.de, err = time.ParseInLocation("02/01/2006", de, time.Local); err != nil {
			return f, fmt.Errorf("-de inválido %q (use DD/MM/AAAA)", de)
		}
	}
	if ate != "" {
		d, err := time.ParseInLocation("02/01/2006", ate, time.Local)
		if err != nil {
			return f, fmt.Errorf("-ate inválido %q (use DD/MM/AAAA)", ate)
		}
		f.ate = d.AddDate(0, 0, 1) // inclui o dia inteiro
	}
	return f, nil
}

func (f Filtro) ativo() bool { return !f.de.IsZero() || !f.ate.IsZero() }

// passa diz se a linha está dentro do período. Sem filtro, tudo passa;
// com filtro, linhas sem data legível são descartadas.
func (f Filtro) passa(linha string) bool {
	if !f.ativo() {
		return true
	}
	t, ok := parseTempo(linha)
	if !ok {
		return false
	}
	return (f.de.IsZero() || !t.Before(f.de)) && (f.ate.IsZero() || t.Before(f.ate))
}

func (f Filtro) String() string {
	ini, fim := "início", "agora"
	if !f.de.IsZero() {
		ini = f.de.Format("02/01/2006")
	}
	if !f.ate.IsZero() {
		fim = f.ate.AddDate(0, 0, -1).Format("02/01/2006")
	}
	return ini + " até " + fim
}

// descricao devolve o período em texto, ou "completo" quando não há filtro.
func (f Filtro) descricao() string {
	if !f.ativo() {
		return "completo"
	}
	return f.String()
}

// Pendentes é a lista de IPs que o relatório propôs banir. Fica em disco para que
// o programa que tratar a resposta aja sobre ESTA lista, e não sobre dados vindos do botão.
type Pendentes struct {
	ID     string    `json:"id"`
	Criado time.Time `json:"criado"`
	IPs    []string  `json:"ips"`
}

const arquivoPendentes = "log/pendentes.json"

func salvarPendentes(ips []string) (string, error) {
	p := Pendentes{ID: time.Now().Format("20060102150405"), Criado: time.Now(), IPs: ips}
	dados, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return "", err
	}
	return p.ID, os.WriteFile(arquivoPendentes, dados, 0o600)
}

// tecladoBan devolve o JSON do teclado inline: duração do ban (24h / 7d / permanente) ou "Não".
// Os rótulos seguem UFW_DURACAO_CURTA e UFW_DURACAO_LONGA, as mesmas variáveis do ufwbot.
// O callback_data leva só uma ação e o ID da lista (limite de 64 bytes do Telegram), nunca os IPs.
func tecladoBan(id string) string {
	tec := map[string]any{"inline_keyboard": [][]map[string]string{{
		{"text": "✅ " + rotuloDuracao(envOu("UFW_DURACAO_CURTA", "24h")), "callback_data": "banir_24h:" + id},
		{"text": "✅ " + rotuloDuracao(envOu("UFW_DURACAO_LONGA", "7d")), "callback_data": "banir_7d:" + id},
		{"text": "♾ Permanente", "callback_data": "banir_perm:" + id},
	}, {
		{"text": "❌ Não", "callback_data": "banir_nao:" + id},
	}}}
	b, _ := json.Marshal(tec)
	return string(b)
}

// rotuloDuracao devolve o texto do botão; "24h" fica "24h", "168h" vira "7d".
func rotuloDuracao(s string) string {
	if d, err := time.ParseDuration(s); err == nil && d > 0 && d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
	return s
}

// ---------- Aba: IPs no limite ou perto dele ----------

// fracaoAlerta define "perto do limite": a partir de 70% dele.
const fracaoAlerta = 0.7

// abaLimite compara, para cada IP, as tentativas de login no SSH (somadas de todos os usuários)
// e os bloqueios do UFW com o limite. Considera a MAIOR das duas contagens.
// Devolve as linhas da aba, os IPs que atingiram o limite sem estar banidos (pendentes de ban)
// e quantos estão perto do limite.
func abaLimite(ufwLog string, flt Filtro, bans map[string]*InfoBan, usuarios [][]any, limite int) ([][]any, []string, int) {
	ssh := map[string]int{}
	for _, l := range usuarios {
		ssh[l[1].(string)] += l[2].(int)
	}
	ufw := map[string]int{}
	if linhas, err := lerLinhas(ufwLog); err == nil {
		for _, l := range linhas {
			if !strings.Contains(l, "[UFW BLOCK]") || !flt.passa(l) {
				continue
			}
			for _, par := range strings.Fields(l) {
				if ip, ok := strings.CutPrefix(par, "SRC="); ok {
					ufw[ip]++
					break
				}
			}
		}
	}

	ips := map[string]bool{}
	for ip := range ssh {
		ips[ip] = true
	}
	for ip := range ufw {
		ips[ip] = true
	}

	minAlerta := int(float64(limite)*fracaoAlerta + 0.999) // arredonda para cima
	var out [][]any
	var pendentes []string
	perto := 0
	for ip := range ips {
		maior := max(ssh[ip], ufw[ip])
		if maior < minAlerta {
			continue
		}
		var situacao string
		switch b := bans[ip]; {
		case b != nil && b.banido():
			situacao = "Já banido"
		case maior >= limite:
			situacao = "NO LIMITE — banir"
			pendentes = append(pendentes, ip)
		default:
			situacao = "Perto do limite"
			perto++
		}
		out = append(out, []any{ip, ssh[ip], ufw[ip], maior, float64(maior) / float64(limite), situacao})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i][3].(int), out[j][3].(int)
		if a != b {
			return a > b
		}
		return out[i][0].(string) < out[j][0].(string)
	})
	sort.Strings(pendentes)
	return out, pendentes, perto
}

// reDeny pega as regras criadas por "ufw deny from <ip>" na saída de "ufw status".
var reDeny = regexp.MustCompile(`^Anywhere(?: \(v6\))?\s+DENY(?: IN)?\s+(\S+)\s*$`)

// mesclarBansUfw marca como banidos (agora) os IPs com regra "deny from" no ufw que o
// fail2ban não conhece, para que não voltem a ser propostos para ban.
func mesclarBansUfw(bans map[string]*InfoBan, saidaUfw string) {
	for _, l := range strings.Split(saidaUfw, "\n") {
		l, _, _ = strings.Cut(l, " #")
		m := reDeny.FindStringSubmatch(strings.TrimSpace(l))
		if m == nil {
			continue
		}
		a := net.ParseIP(m[1])
		if a == nil {
			continue
		}
		ip := a.String()
		if x := bans[ip]; x != nil && x.banido() {
			continue
		}
		if bans[ip] == nil {
			bans[ip] = &InfoBan{jail: "ufw"}
		}
		bans[ip].bans++
		bans[ip].ultBan = time.Now()
	}
}
