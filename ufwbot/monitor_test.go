package main

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// monitorFalso devolve um monitor com leituras fixas e um relógio manual.
func monitorFalso(t *testing.T) (*Monitor, *[]string, *time.Time) {
	var msgs []string
	agora := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	m := &Monitor{
		enviar:    func(s string) error { msgs = append(msgs, s); return nil },
		agora:     func() time.Time { return agora },
		dormir:    func(time.Duration) {},
		intervalo: 30 * time.Second, sustentado: 2,
		limCPU: 90, limMem: 90, limDisco: 90, discoPath: "/", tlsDias: 14,
		arqEstado: filepath.Join(t.TempDir(), "monitor.json"),
		lerCPU:    func() (uint64, uint64, error) { return 0, 0, errors.New("x") },
		lerMem:    func() (float64, uint64, uint64, error) { return 10, 1, 10, nil },
		lerDisco:  func(string) (float64, uint64, uint64, error) { return 10, 1, 10, nil },
		lerUptime: func() (time.Duration, error) { return time.Hour, nil },
		lerBootID: func() string { return "boot1" },
		lerLoad:   func() string { return "0.1 0.1 0.1" },
		servico:   func(string) estadoServico { return estadoServico{Achado: true, Ativo: true, Estado: "active"} },
		abrirTCP:  func(string) error { return nil },
		checarURL: func(string) error { return nil },
		certExpira: func(string) (time.Time, error) {
			return agora.Add(90 * 24 * time.Hour), nil
		},
		containers: func() ([]container, error) { return nil, nil },
	}
	return m, &msgs, &agora
}

func TestParseCPUeMem(t *testing.T) {
	o, tot, err := parseCPU("cpu  100 0 50 800 50 0 0 0 0 0")
	if err != nil || o != 850 || tot != 1000 {
		t.Fatalf("cpu: %d %d %v", o, tot, err)
	}
	pct, usado, total, err := parseMem("MemTotal: 1000 kB\nMemFree: 1 kB\nMemAvailable: 250 kB\n")
	if err != nil || pct != 75 || usado != 750*1024 || total != 1000*1024 {
		t.Fatalf("mem: %v %d %d %v", pct, usado, total, err)
	}
	if _, _, _, err := parseMem("MemTotal: 1 kB"); err == nil {
		t.Fatal("meminfo incompleto deveria falhar")
	}
}

func TestParseSystemd(t *testing.T) {
	if s := parseSystemd("LoadState=loaded\nActiveState=failed\n"); !s.Achado || s.Ativo || s.Estado != "failed" {
		t.Fatalf("%+v", s)
	}
	if s := parseSystemd("LoadState=not-found\nActiveState=inactive\n"); s.Achado {
		t.Fatalf("não instalado deveria ser ignorado: %+v", s)
	}
}

func TestServicoCaiEVolta(t *testing.T) {
	m, msgs, _ := monitorFalso(t)
	m.servicos = []string{"nginx", "ausente"}
	ativo := false
	m.servico = func(u string) estadoServico {
		if u == "ausente" {
			return estadoServico{}
		}
		return estadoServico{Achado: true, Ativo: ativo, Estado: "failed"}
	}
	m.ciclo() // 1ª falha: ainda não avisa (evita alarme em reinício rápido)
	if len(*msgs) != 0 {
		t.Fatalf("avisou cedo: %v", *msgs)
	}
	m.ciclo()
	m.ciclo() // não repete
	if len(*msgs) != 1 || !strings.Contains((*msgs)[0], "nginx parou") {
		t.Fatalf("esperava 1 aviso de queda: %v", *msgs)
	}
	ativo = true
	m.ciclo()
	if len(*msgs) != 2 || !strings.Contains((*msgs)[1], "nginx voltou") {
		t.Fatalf("esperava aviso de volta: %v", *msgs)
	}
}

func TestCPUSustentadaComHisterese(t *testing.T) {
	m, msgs, _ := monitorFalso(t)
	var ocioso, total uint64
	m.lerCPU = func() (uint64, uint64, error) { total += 100; return ocioso, total, nil } // ocioso fixo: 100% em uso
	m.ciclo()                                                                             // só prepara a amostra
	m.ciclo()                                                                             // 1ª acima
	if len(*msgs) != 0 {
		t.Fatalf("avisou antes de ser sustentada: %v", *msgs)
	}
	m.ciclo()
	if len(*msgs) != 1 || !strings.Contains((*msgs)[0], "CPU alta") {
		t.Fatalf("esperava alerta de CPU: %v", *msgs)
	}
	m.lerCPU = func() (uint64, uint64, error) { total += 100; ocioso += 12; return ocioso, total, nil } // 88%: dentro da histerese
	m.ciclo()
	if len(*msgs) != 1 {
		t.Fatalf("não devia normalizar a 88%%: %v", *msgs)
	}
	m.lerCPU = func() (uint64, uint64, error) { total += 100; ocioso += 50; return ocioso, total, nil }
	m.ciclo()
	if len(*msgs) != 2 || !strings.Contains((*msgs)[1], "normalizou") {
		t.Fatalf("esperava normalização: %v", *msgs)
	}
}

func TestDiscoRepeteALembrete(t *testing.T) {
	m, msgs, agora := monitorFalso(t)
	m.lerDisco = func(string) (float64, uint64, uint64, error) { return 95, 95, 100, nil }
	m.ciclo()
	m.ciclo()
	*agora = agora.Add(7 * time.Hour)
	m.ciclo()
	if len(*msgs) != 2 {
		t.Fatalf("esperava aviso + lembrete: %v", *msgs)
	}
}

func TestContainers(t *testing.T) {
	cases := map[string]container{
		"":                    {"job", "exited", "Exited (0) 2 hours ago"},
		"saiu com código 137": {"api", "exited", "Exited (137) 1 minute ago"},
		"unhealthy":           {"db", "running", "Up 3 hours (unhealthy)"},
		"restarting":          {"w", "restarting", "Restarting (1) 5 seconds ago"},
	}
	for want, c := range cases {
		if got := problemaContainer(c); got != want {
			t.Errorf("%+v: %q, queria %q", c, got, want)
		}
	}
	m, msgs, _ := monitorFalso(t)
	m.docker = true
	lista := []container{{"api", "exited", "Exited (1) now"}}
	m.containers = func() ([]container, error) { return lista, nil }
	m.ciclo()
	m.ciclo()
	lista = nil // container removido: encerra o alerta
	m.ciclo()
	if len(*msgs) != 2 || !strings.Contains((*msgs)[0], "api") || !strings.Contains((*msgs)[1], "não existe mais") {
		t.Fatalf("docker: %v", *msgs)
	}
}

func TestTLS(t *testing.T) {
	m, msgs, agora := monitorFalso(t)
	m.tlsHosts = []string{"a.com", "b.com"}
	m.certExpira = func(h string) (time.Time, error) {
		if h == "b.com" {
			return time.Time{}, errors.New("certificate has expired")
		}
		return agora.Add(5*24*time.Hour + time.Hour), nil
	}
	m.ciclo()
	if len(*msgs) != 2 {
		t.Fatalf("esperava 2 alertas TLS: %v", *msgs)
	}
	j := strings.Join(*msgs, "|")
	if !strings.Contains(j, "a.com expira em 5 dia(s)") || !strings.Contains(j, "b.com inválido") {
		t.Fatalf("textos: %v", *msgs)
	}
	m.ciclo() // dentro de 1h: não consulta nem repete
	if len(*msgs) != 2 {
		t.Fatalf("repetiu: %v", *msgs)
	}
}

func TestReinicioDaVPSeDoBot(t *testing.T) {
	m, msgs, agora := monitorFalso(t)
	m.iniciar() // primeira execução: só grava
	if len(*msgs) != 0 {
		t.Fatalf("primeira execução não avisa: %v", *msgs)
	}
	*agora = agora.Add(10 * time.Minute)
	m.iniciar() // mesmo boot, 10min sem sinal: o bot foi reiniciado
	if len(*msgs) != 1 || !strings.Contains((*msgs)[0], "Monitor reiniciado") {
		t.Fatalf("reinício do bot: %v", *msgs)
	}
	*agora = agora.Add(5 * time.Minute)
	m.lerBootID = func() string { return "boot2" }
	m.iniciar()
	if len(*msgs) != 2 || !strings.Contains((*msgs)[1], "reiniciou. Sem sinal por 5m") {
		t.Fatalf("reinício da VPS: %v", *msgs)
	}
	*agora = agora.Add(10 * time.Second)
	m.iniciar() // reinício rápido do bot dentro de 3 intervalos: sem barulho
	if len(*msgs) != 2 {
		t.Fatalf("avisou à toa: %v", *msgs)
	}
}

func TestPainelEComando(t *testing.T) {
	b, _, _ := novoBot(t)
	b.processar(msg(42, 42, "/painel"))
	if ultimaMensagem != "Monitor desligado (MON_INTERVALO=0)." {
		t.Fatalf("sem monitor: %q", ultimaMensagem)
	}
	m, _, _ := monitorFalso(t)
	m.servicos, m.tlsHosts, m.docker = []string{"nginx", "ausente"}, []string{"a.com"}, true
	m.servico = func(u string) estadoServico {
		if u == "ausente" {
			return estadoServico{}
		}
		return estadoServico{Achado: true, Ativo: false, Estado: "failed"}
	}
	b.mon = m
	b.processar(msg(42, 42, "/painel"))
	for _, quer := range []string{"RAM: 10%", "Disco /: 10%", "🔴 nginx", "a.com: 90 dias", "Uptime: 1h 0m"} {
		if !strings.Contains(ultimaMensagem, quer) {
			t.Errorf("painel sem %q:\n%s", quer, ultimaMensagem)
		}
	}
	if strings.Contains(ultimaMensagem, "ausente") || !strings.Contains(ultimoTeclado, "painel:atualizar") {
		t.Errorf("serviço ausente deve sumir e deve ter botão:\n%s\n%s", ultimaMensagem, ultimoTeclado)
	}
	b.processar(msg(7, 7, "/painel")) // outro usuário: ignorado
}

func TestSubcomandoDeploy(t *testing.T) {
	b, _, _ := novoBot(t)
	if c := b.subcomando([]string{"deploy", "api", "ok", "v1.2.3"}); c != 0 ||
		!strings.Contains(ultimaMensagem, "🚀 Deploy de api concluído") || !strings.HasSuffix(ultimaMensagem, "v1.2.3") {
		t.Fatalf("%d %q", c, ultimaMensagem)
	}
	b.subcomando([]string{"deploy", "api", "falha"})
	if !strings.Contains(ultimaMensagem, "❌ Deploy de api FALHOU") {
		t.Fatalf("%q", ultimaMensagem)
	}
	if c := b.subcomando([]string{"deploy", "api"}); c != 2 {
		t.Fatalf("uso errado deveria dar 2, deu %d", c)
	}
}
