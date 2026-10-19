package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const saidaUfw = `Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
Anywhere                   DENY        203.0.113.5
Anywhere                   DENY IN     198.51.100.7
Anywhere (v6)              DENY        2001:db8::1
Anywhere                   DENY        203.0.113.5
`

func msg(quem, chat int64, texto string) Update {
	m := &Mensagem{Text: texto}
	m.From.ID, m.Chat.ID = quem, chat
	return Update{UpdateID: 1, Message: m}
}

func comUfw(b *Bot, chamadas *[][]string) {
	b.ufw = func(args ...string) (string, error) {
		*chamadas = append(*chamadas, args)
		if args[0] == "status" {
			return saidaUfw, nil
		}
		return "", nil
	}
}

func TestStatusEBanidos(t *testing.T) {
	b, _, _ := novoBot(t)
	var ch [][]string
	comUfw(b, &ch)
	b.processar(msg(42, 42, "/status"))
	if !strings.Contains(ultimaMensagem, "✅ ativo") || !strings.Contains(ultimaMensagem, "Regras: 5") || !strings.Contains(ultimaMensagem, "IPs banidos: 3") {
		t.Fatalf("status errado: %q", ultimaMensagem)
	}
	b.processar(msg(42, 42, "/banidos"))
	if ultimaMensagem != "IPs banidos:\n203.0.113.5\n198.51.100.7\n2001:db8::1" {
		t.Fatalf("banidos errado: %q", ultimaMensagem)
	}
}

func TestDesbanir(t *testing.T) {
	b, _, _ := novoBot(t)
	var ch [][]string
	comUfw(b, &ch)
	b.processar(msg(42, 42, "/desbanir 203.0.113.5"))
	if len(ch) != 2 || strings.Join(ch[1], " ") != "delete deny from 203.0.113.5" {
		t.Fatalf("chamadas erradas: %v", ch)
	}
	for _, ruim := range []string{"/desbanir", "/desbanir naoeip", "/desbanir 192.0.2.9", "/desbanir 1.1.1.1; reboot"} {
		ch = nil
		b.processar(msg(42, 42, ruim))
		for _, c := range ch {
			if c[0] == "delete" {
				t.Fatalf("%q não deveria apagar regra", ruim)
			}
		}
	}
	// ufw falhando
	b.ufw = func(args ...string) (string, error) {
		if args[0] == "delete" {
			return "", errors.New("x")
		}
		return saidaUfw, nil
	}
	b.processar(msg(42, 42, "/desbanir 198.51.100.7"))
	if !strings.Contains(ultimaMensagem, "Falha") {
		t.Fatalf("esperava falha: %q", ultimaMensagem)
	}
}

func TestTop(t *testing.T) {
	b, _, _ := novoBot(t)
	agora := time.Now()
	iso := agora.Format(time.RFC3339)
	antigo := agora.AddDate(0, 0, -2).Format(time.RFC3339)
	var sb strings.Builder
	for i := 0; i < 3; i++ {
		sb.WriteString(iso + " h kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.5 DST=1.1.1.1\n")
	}
	sb.WriteString(iso + " h kernel: [UFW BLOCK] IN=eth0 SRC=198.51.100.7 DST=1.1.1.1\n")
	sb.WriteString(iso + " h kernel: [UFW ALLOW] IN=eth0 SRC=192.0.2.1 DST=1.1.1.1\n")
	sb.WriteString(antigo + " h kernel: [UFW BLOCK] IN=eth0 SRC=192.0.2.2 DST=1.1.1.1\n")
	b.logUfw = filepath.Join(t.TempDir(), "ufw.log")
	os.WriteFile(b.logUfw, []byte(sb.String()), 0o600)
	b.processar(msg(42, 42, "/top"))
	if ultimaMensagem != "Top IPs de hoje (bloqueios no UFW):\n1. 203.0.113.5 — 3\n2. 198.51.100.7 — 1" {
		t.Fatalf("top errado: %q", ultimaMensagem)
	}
}

func TestRelatorio(t *testing.T) {
	b, _, _ := novoBot(t)
	n := 0
	b.relatorio = func() error { n++; return nil }
	b.processar(msg(42, 42, "/relatorio"))
	if n != 1 {
		t.Fatalf("relatório rodou %d vezes", n)
	}
	b.relatorio = func() error { return errors.New("x") }
	b.processar(msg(42, 42, "/relatorio"))
	if !strings.Contains(ultimaMensagem, "Falha") {
		t.Fatalf("esperava falha: %q", ultimaMensagem)
	}
}

func TestComandosSoParaChatAutorizado(t *testing.T) {
	b, chamadas, _ := novoBot(t)
	usou := false
	b.ufw = func(...string) (string, error) { usou = true; return saidaUfw, nil }
	b.relatorio = func() error { usou = true; return nil }
	for _, c := range []string{"/status", "/banidos", "/desbanir 203.0.113.5", "/top", "/relatorio"} {
		b.processar(msg(999, 999, c)) // outra pessoa
		b.processar(msg(42, 999, c))  // chat diferente
		b.processar(msg(999, 42, c))  // usuário diferente
	}
	if usou || len(*chamadas) != 0 {
		t.Fatalf("comando de não autorizado teve efeito (usou=%v, chamadas=%v)", usou, *chamadas)
	}
}

func TestSaudacaoPerguntaOQueFazer(t *testing.T) {
	b, _, _ := novoBot(t)
	b.agora = func() time.Time { return time.Date(2026, 10, 19, 16, 5, 0, 0, time.Local) }
	for _, txt := range []string{"Oi", "olá!", "Bom dia", "/start"} {
		ultimaMensagem, ultimoTeclado = "", ""
		b.processar(msg(42, 42, txt))
		want := "Boa tarde! 👋\n📅 segunda-feira, 19/10/2026\n🕓 16:05\n\nO que deseja fazer?"
		if ultimaMensagem != want || !strings.Contains(ultimoTeclado, "menu:status") {
			t.Fatalf("%q: resposta errada %q / %q", txt, ultimaMensagem, ultimoTeclado)
		}
		if strings.Contains(ultimaMensagem, "/status") {
			t.Fatal("não deveria listar comandos")
		}
	}
	ultimaMensagem = ""
	b.processar(msg(42, 42, "qualquer coisa"))
	b.processar(msg(999, 999, "oi")) // não autorizado
	if ultimaMensagem != "" {
		t.Fatalf("não deveria responder: %q", ultimaMensagem)
	}
	b.processar(msg(42, 42, "/ajuda"))
	if ultimaMensagem != textoAjuda {
		t.Fatalf("/ajuda deve listar os comandos: %q", ultimaMensagem)
	}
}

func TestSaudacaoPeriodos(t *testing.T) {
	for h, want := range map[int]string{4: "Boa noite", 5: "Bom dia", 11: "Bom dia", 12: "Boa tarde", 17: "Boa tarde", 18: "Boa noite", 23: "Boa noite"} {
		if got := textoSaudacao(time.Date(2026, 10, 19, h, 0, 0, 0, time.Local)); !strings.HasPrefix(got, want+"!") {
			t.Errorf("%dh: %q", h, got)
		}
	}
}

func TestAtalhosDaSaudacao(t *testing.T) {
	b, _, _ := novoBot(t)
	var ch [][]string
	comUfw(b, &ch)
	b.processar(clique(42, 42, "menu:status"))
	if !strings.Contains(ultimaMensagem, "✅ ativo") {
		t.Fatalf("atalho status: %q", ultimaMensagem)
	}
	b.processar(clique(42, 42, "menu:banidos"))
	if !strings.HasPrefix(ultimaMensagem, "IPs banidos:") {
		t.Fatalf("atalho banidos: %q", ultimaMensagem)
	}
	ultimaMensagem = ""
	b.processar(clique(999, 999, "menu:status")) // não autorizado
	if ultimaMensagem != "" {
		t.Fatal("atalho de não autorizado respondeu")
	}
}

func TestBanTemporarioEExpiracao(t *testing.T) {
	b, _, banidos := novoBot(t)
	agora := time.Date(2026, 10, 19, 12, 0, 0, 0, time.Local)
	b.agora = func() time.Time { return agora }
	var ch [][]string
	comUfw(b, &ch)

	b.processar(clique(42, 42, "banir_24h:A1"))
	if len(*banidos) != 2 || !strings.Contains(ultimaMensagem, "Duração: 1d") {
		t.Fatalf("ban 24h: %v %q", *banidos, ultimaMensagem)
	}
	bans := b.lerBans()
	if !bans["203.0.113.5"].Expira.Equal(agora.Add(24 * time.Hour)) {
		t.Fatalf("expiração errada: %+v", bans)
	}

	// /banidos mostra a expiração.
	b.processar(msg(42, 42, "/banidos"))
	if !strings.Contains(ultimaMensagem, "203.0.113.5 — expira 20/10 12:00") {
		t.Fatalf("banidos: %q", ultimaMensagem)
	}

	// Antes do prazo nada acontece; depois, o ban é removido do ufw e do arquivo.
	ch = nil
	if f := b.expirarVencidos(); len(f) != 0 || len(ch) != 0 {
		t.Fatalf("expirou cedo: %v %v", f, ch)
	}
	agora = agora.Add(25 * time.Hour)
	f := b.expirarVencidos()
	if len(f) != 2 || len(ch) != 2 || strings.Join(ch[0][:3], " ") != "delete deny from" {
		t.Fatalf("expiração: %v %v", f, ch)
	}
	if len(b.lerBans()) != 0 {
		t.Fatal("bans.json deveria estar vazio")
	}
}

func TestBanPermanenteEExpiracaoQueFalha(t *testing.T) {
	b, _, _ := novoBot(t)
	agora := time.Now()
	b.agora = func() time.Time { return agora }
	b.processar(clique(42, 42, "banir_perm:A1"))
	if !strings.Contains(ultimaMensagem, "Duração: permanente") {
		t.Fatalf("msg: %q", ultimaMensagem)
	}
	agora = agora.AddDate(1, 0, 0)
	b.ufw = func(...string) (string, error) { t.Fatal("permanente não expira"); return "", nil }
	b.expirarVencidos()

	// Regra que já não existe: esquece o registro. Regra que existe e falhou: mantém.
	b.registrarBan("203.0.113.5", time.Hour)
	b.registrarBan("198.51.100.7", time.Hour)
	agora = agora.Add(2 * time.Hour)
	b.ufw = func(a ...string) (string, error) {
		if a[0] == "delete" {
			return "", errors.New("falhou")
		}
		return "Status: active\n--\nAnywhere  DENY  198.51.100.7\n", nil
	}
	b.expirarVencidos()
	bans := b.lerBans()
	if _, ok := bans["203.0.113.5"]; ok {
		t.Fatal("registro de regra inexistente deveria sumir")
	}
	if _, ok := bans["198.51.100.7"]; !ok {
		t.Fatal("regra que ainda existe deve ficar para tentar de novo")
	}
}

func TestParseDuracao(t *testing.T) {
	for in, want := range map[string]time.Duration{"24h": 24 * time.Hour, "7d": 168 * time.Hour, "90m": 90 * time.Minute} {
		if got, err := parseDuracao(in); err != nil || got != want {
			t.Fatalf("%s: %v %v", in, got, err)
		}
	}
	for _, ruim := range []string{"", "x", "0d", "-1h", "d"} {
		if _, err := parseDuracao(ruim); err == nil {
			t.Fatalf("%q deveria falhar", ruim)
		}
	}
}

func TestRegistrarMenu(t *testing.T) {
	b, chamadas, _ := novoBot(t)
	b.registrarMenu()
	if strings.Join(*chamadas, ",") != "/botT/setMyCommands,/botT/setChatMenuButton" {
		t.Fatalf("chamadas: %v", *chamadas)
	}
	j, _ := json.Marshal(comandosMenu)
	if !strings.HasPrefix(string(j), `[{"command":"status","description":`) {
		t.Fatalf("JSON fora do formato do Telegram: %s", j)
	}
	for _, c := range comandosMenu {
		if c.Command != strings.ToLower(c.Command) || len(c.Description) == 0 || len(c.Description) > 256 {
			t.Fatalf("comando inválido para o Telegram: %+v", c)
		}
	}
}
