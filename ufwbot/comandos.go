package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// maxLista limita quantos itens cabem numa resposta (o Telegram aceita 4096 caracteres).
const maxLista = 100

// reDeny pega as regras criadas por "ufw deny from <ip>" na saída de "ufw status".
var reDeny = regexp.MustCompile(`^Anywhere(?: \(v6\))?\s+DENY(?: IN)?\s+(\S+)\s*$`)

const textoAjuda = `Olá! Comandos disponíveis:
/status — resumo do UFW
/banidos — IPs banidos
/desbanir <ip> — remove o ban de um IP
/top — 10 IPs com mais bloqueios hoje
/relatorio — gera e envia o relatório agora
/painel — CPU, RAM, disco, serviços, Docker e certificados`

// ehSaudacao diz se o texto é só um cumprimento ("oi", "Olá!", "bom dia"...).
func ehSaudacao(texto string) bool {
	t := strings.ToLower(strings.Trim(strings.TrimSpace(texto), "!.?, "))
	switch t {
	case "oi", "olá", "ola", "oie", "hey", "hello", "bom dia", "boa tarde", "boa noite", "menu", "ajuda":
		return true
	}
	return false
}

// comando trata uma mensagem de texto. Só o chat autorizado é atendido; o resto é ignorado em silêncio.
func (b *Bot) comando(m *Mensagem) {
	if m.From.ID != b.chatAutorizado || m.Chat.ID != b.chatAutorizado {
		log.Printf("mensagem ignorada de usuário não autorizado (%d)", m.From.ID)
		return
	}
	campos := strings.Fields(m.Text)
	if len(campos) == 0 {
		return
	}
	if !strings.HasPrefix(campos[0], "/") {
		if ehSaudacao(m.Text) {
			b.saudar()
		}
		return
	}
	cmd, _, _ := strings.Cut(campos[0], "@") // "/status@meubot" em grupos
	switch cmd {
	case "/status":
		b.cmdStatus()
	case "/banidos":
		b.cmdBanidos()
	case "/desbanir":
		if len(campos) != 2 {
			b.mensagem("Uso: /desbanir <ip>")
			return
		}
		b.cmdDesbanir(campos[1])
	case "/top":
		b.cmdTop()
	case "/relatorio":
		b.cmdRelatorio()
	case "/painel":
		b.cmdPainel()
	case "/start":
		b.saudar()
	default: // inclui /ajuda
		b.mensagem(textoAjuda)
	}
}

// rodarUfw executa o ufw sem shell e devolve a saída.
func rodarUfw(args ...string) (string, error) {
	out, err := exec.Command("ufw", args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// ipsBanidos devolve os IPs com regra "deny from" no ufw, sem repetir (v4 e v6 separados).
func ipsBanidos(saida string) []string {
	var ips []string
	visto := map[string]bool{}
	for _, l := range strings.Split(saida, "\n") {
		l, _, _ = strings.Cut(l, " #")
		m := reDeny.FindStringSubmatch(strings.TrimSpace(l))
		if m == nil {
			continue
		}
		addr := net.ParseIP(m[1])
		if addr == nil || visto[addr.String()] {
			continue
		}
		visto[addr.String()] = true
		ips = append(ips, addr.String())
	}
	return ips
}

// contarRegras conta as linhas de regra depois do separador "--" de "ufw status".
func contarRegras(saida string) int {
	n, dentro := 0, false
	for _, l := range strings.Split(saida, "\n") {
		switch {
		case strings.HasPrefix(l, "--"):
			dentro = true
		case dentro && strings.TrimSpace(l) != "":
			n++
		}
	}
	return n
}

func (b *Bot) cmdStatus() {
	saida, err := b.ufw("status")
	if err != nil {
		b.mensagem("Não consegui consultar o ufw.")
		return
	}
	ativo := "❌ inativo"
	if strings.Contains(saida, "Status: active") {
		ativo = "✅ ativo"
	}
	b.mensagem(fmt.Sprintf("UFW: %s\nRegras: %d\nIPs banidos: %d", ativo, contarRegras(saida), len(ipsBanidos(saida))))
}

func (b *Bot) cmdBanidos() {
	saida, err := b.ufw("status")
	if err != nil {
		b.mensagem("Não consegui consultar o ufw.")
		return
	}
	ips := ipsBanidos(saida)
	if len(ips) == 0 {
		b.mensagem("Nenhum IP banido.")
		return
	}
	extra := ""
	if len(ips) > maxLista {
		extra = fmt.Sprintf("\n... e mais %d", len(ips)-maxLista)
		ips = ips[:maxLista]
	}
	bans := b.lerBans()
	for i, ip := range ips {
		if x, ok := bans[ip]; ok {
			ips[i] += " — " + x.descricao()
		}
	}
	b.mensagem(fmt.Sprintf("IPs banidos:\n%s%s", strings.Join(ips, "\n"), extra))
}

func (b *Bot) cmdDesbanir(arg string) {
	addr := net.ParseIP(arg)
	if addr == nil {
		b.mensagem("IP inválido.")
		return
	}
	ip := addr.String() // forma canônica; vai como argumento separado, sem shell
	saida, err := b.ufw("status")
	if err != nil {
		b.mensagem("Não consegui consultar o ufw.")
		return
	}
	achou := false
	for _, x := range ipsBanidos(saida) {
		achou = achou || x == ip
	}
	if !achou {
		b.mensagem(ip + " não está banido.")
		return
	}
	if _, err := b.ufw("delete", "deny", "from", ip); err != nil {
		log.Printf("falha ao desbanir %s: %v", ip, err)
		b.mensagem("⚠️ Falha ao desbanir " + ip)
		return
	}
	b.esquecerBan(ip)
	b.mensagem("✅ " + ip + " desbanido.")
}

func (b *Bot) cmdTop() {
	top, err := topHoje(b.logUfw, time.Now())
	if err != nil {
		b.mensagem("Não consegui ler o log do UFW.")
		return
	}
	if len(top) == 0 {
		b.mensagem("Nenhuma tentativa bloqueada hoje.")
		return
	}
	var sb strings.Builder
	sb.WriteString("Top IPs de hoje (bloqueios no UFW):")
	for i, kv := range top {
		fmt.Fprintf(&sb, "\n%d. %s — %d", i+1, kv.ip, kv.n)
	}
	b.mensagem(sb.String())
}

type contagem struct {
	ip string
	n  int
}

// topHoje conta os "[UFW BLOCK]" do dia por SRC e devolve os 10 maiores.
func topHoje(caminho string, agora time.Time) ([]contagem, error) {
	f, err := os.Open(caminho)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	iso, syslog := agora.Format("2006-01-02"), agora.Format("Jan _2")
	cont := map[string]int{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		l := sc.Text()
		if !strings.Contains(l, "[UFW BLOCK]") || !(strings.HasPrefix(l, iso) || strings.HasPrefix(l, syslog)) {
			continue
		}
		for _, par := range strings.Fields(l) {
			if ip, ok := strings.CutPrefix(par, "SRC="); ok {
				cont[ip]++
				break
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	var out []contagem
	for ip, n := range cont {
		out = append(out, contagem{ip, n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].n != out[j].n {
			return out[i].n > out[j].n
		}
		return out[i].ip < out[j].ip
	})
	if len(out) > 10 {
		out = out[:10]
	}
	return out, nil
}

func (b *Bot) cmdRelatorio() {
	b.mensagem("Gerando o relatório de hoje...")
	if err := b.relatorio(); err != nil {
		log.Println("falha no relatório:", err)
		b.mensagem("⚠️ Falha ao gerar o relatório.")
	}
}

// rodarRelatorio devolve a função que executa o ufwrelatorio (-hoje). Ele mesmo envia o xlsx
// ao Telegram, pois herda TELEGRAM_TOKEN/TELEGRAM_CHAT_ID. Roda na pasta que contém "log/".
func (b *Bot) rodarRelatorio(bin string) func() error {
	return func() error {
		cmd := exec.Command(bin, "-hoje")
		cmd.Dir = filepath.Dir(filepath.Dir(b.arquivoPendentes))
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
}

// comandosMenu são os comandos que o Telegram mostra ao digitar "/" e no botão de menu.
var comandosMenu = []struct {
	Command     string `json:"command"`
	Description string `json:"description"`
}{
	{"status", "resumo do UFW: ativo, regras e IPs banidos"},
	{"banidos", "lista os IPs banidos"},
	{"desbanir", "remove o ban de um IP (/desbanir 1.2.3.4)"},
	{"top", "os 10 IPs com mais bloqueios hoje"},
	{"relatorio", "gera e envia o relatório agora"},
	{"painel", "estado da VPS: CPU, RAM, disco, serviços e TLS"},
	{"ajuda", "mostra os comandos disponíveis"},
}

// registrarMenu publica a lista de comandos só para o chat autorizado (escopo "chat") e
// liga o botão de menu ☰ ao lado do campo de texto. Falhas só vão para o log.
func (b *Bot) registrarMenu() {
	cmds, _ := json.Marshal(comandosMenu)
	chat := strconv.FormatInt(b.chatAutorizado, 10)
	if err := b.chamar("setMyCommands", url.Values{
		"commands": {string(cmds)},
		"scope":    {`{"type":"chat","chat_id":` + chat + `}`},
	}, nil); err != nil {
		log.Println("não consegui registrar o menu de comandos:", err)
		return
	}
	if err := b.chamar("setChatMenuButton", url.Values{
		"chat_id":     {chat},
		"menu_button": {`{"type":"commands"}`},
	}, nil); err != nil {
		log.Println("não consegui ligar o botão de menu:", err)
	}
}

var diasSemana = [...]string{"domingo", "segunda-feira", "terça-feira", "quarta-feira", "quinta-feira", "sexta-feira", "sábado"}

// textoSaudacao monta "Bom dia!", a data, a hora e a pergunta.
func textoSaudacao(t time.Time) string {
	cumprimento := "Boa noite"
	switch h := t.Hour(); {
	case h >= 5 && h < 12:
		cumprimento = "Bom dia"
	case h >= 12 && h < 18:
		cumprimento = "Boa tarde"
	}
	return fmt.Sprintf("%s! 👋\n📅 %s, %s\n🕓 %s\n\nO que deseja fazer?",
		cumprimento, diasSemana[t.Weekday()], t.Format("02/01/2006"), t.Format("15:04"))
}

// tecladoSaudacao são os atalhos mostrados junto da saudação.
const tecladoSaudacao = `{"inline_keyboard":[[` +
	`{"text":"📊 Status","callback_data":"menu:status"},` +
	`{"text":"🚫 Banidos","callback_data":"menu:banidos"}],[` +
	`{"text":"🏆 Top de hoje","callback_data":"menu:top"},` +
	`{"text":"📄 Relatório","callback_data":"menu:relatorio"}],[` +
	`{"text":"🖥️ Painel da VPS","callback_data":"menu:painel"}]]}`

func (b *Bot) saudar() {
	b.mensagemComBotoes(textoSaudacao(b.now()), tecladoSaudacao)
}

// atalho trata os botões da saudação (callback "menu:<acao>").
func (b *Bot) atalho(cq *CallbackQuery, acao string) {
	b.responder(cq, "")
	switch acao {
	case "status":
		b.cmdStatus()
	case "banidos":
		b.cmdBanidos()
	case "top":
		b.cmdTop()
	case "relatorio":
		b.cmdRelatorio()
	case "painel":
		b.cmdPainel()
	}
}
