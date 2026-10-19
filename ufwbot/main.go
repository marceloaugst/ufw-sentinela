// ufwbot escuta os botões "Sim/Não" enviados pelo relatório e, se autorizado,
// bane no ufw os IPs listados em pendentes.json.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Pendentes é a lista gravada pelo programa do relatório.
type Pendentes struct {
	ID         string    `json:"id"`
	Criado     time.Time `json:"criado"`
	IPs        []string  `json:"ips"`
	Processado bool      `json:"processado"` // true depois do primeiro clique: cada lista só vale uma vez
}

// Estrutura mínima do que o Telegram devolve em getUpdates.
type Update struct {
	UpdateID      int            `json:"update_id"`
	CallbackQuery *CallbackQuery `json:"callback_query"`
	Message       *Mensagem      `json:"message"`
}

// Mensagem de texto enviada ao bot (usada nos comandos).
type Mensagem struct {
	From struct{ ID int64 } `json:"from"`
	Chat struct{ ID int64 } `json:"chat"`
	Text string             `json:"text"`
}
type CallbackQuery struct {
	ID      string             `json:"id"`
	From    struct{ ID int64 } `json:"from"`
	Data    string             `json:"data"`
	Message *struct {
		MessageID int                `json:"message_id"`
		Chat      struct{ ID int64 } `json:"chat"`
	} `json:"message"`
}

type Bot struct {
	api, token       string
	chatAutorizado   int64
	arquivoPendentes string
	nuncaBanir       map[string]bool // IPs informados em UFW_NUNCA_BANIR (ex.: o seu IP)
	banir            func(ip string) error
	ufw              func(args ...string) (string, error) // executa o ufw (trocável nos testes)
	logUfw           string                               // log do UFW lido por /top
	relatorio        func() error                         // gera e envia o xlsx (trocável nos testes)
	cli              *http.Client

	arquivoBans  string        // bans.json: quando cada ban expira
	duracaoCurta time.Duration // botão "24h" (UFW_DURACAO_CURTA)
	duracaoLonga time.Duration // botão "7d" (UFW_DURACAO_LONGA)
	agora        func() time.Time
	mu           sync.Mutex // protege bans.json (laço do Telegram x rotina de expiração)

	// ban automático (etapa 4)
	autoLimite int           // mais de N tentativas na janela => ban (0 desliga)
	autoJanela time.Duration // UFW_AUTO_JANELA
	logAuth    string
	janelas    map[string][]time.Time // tentativas recentes por IP
	offsets    map[string]int64       // até onde cada log já foi lido
	muAuto     sync.Mutex
	tratados   map[string]bool // IPs já banidos/desfeitos: não banir de novo sozinho

	// alertas em tempo real (etapa 5)
	alertaPico, alertaPortas, alertaMaxHora int           // 0 desliga pico/varredura; máx. de alertas por hora
	alertaJanela, alertaPausa               time.Duration // janela de contagem e pausa entre alertas iguais
	alertasSSH                              bool          // avisar login SSH de IP novo
	arquivoSSH                              string
	eventos                                 []tentativa
	conhecidos                              map[string]time.Time // IPs que já fizeram login SSH
	ultimoAlerta                            map[string]time.Time
	enviados                                []time.Time
	avisouLimite                            bool

	mon *Monitor // monitor da VPS (nil = desligado)
}

func main() {
	token := os.Getenv("TELEGRAM_TOKEN")
	chat, err := strconv.ParseInt(os.Getenv("TELEGRAM_CHAT_ID"), 10, 64)
	if token == "" || err != nil {
		log.Fatal("defina TELEGRAM_TOKEN e TELEGRAM_CHAT_ID (número)")
	}
	b := &Bot{
		api:              envOu("TELEGRAM_API", "https://api.telegram.org"),
		token:            token,
		chatAutorizado:   chat,
		arquivoPendentes: envOu("UFW_PENDENTES", "log/pendentes.json"),
		nuncaBanir:       map[string]bool{},
		banir:            banirNoUfw,
		ufw:              rodarUfw,
		logUfw:           envOu("UFW_LOG", "/var/log/ufw.log"),
		cli:              &http.Client{Timeout: 45 * time.Second},
	}
	if len(os.Args) > 1 {
		os.Exit(b.subcomando(os.Args[1:]))
	}
	b.arquivoBans = envOu("UFW_BANS", filepath.Join(filepath.Dir(b.arquivoPendentes), "bans.json"))
	if b.duracaoCurta, err = parseDuracao(envOu("UFW_DURACAO_CURTA", "24h")); err != nil {
		log.Fatal("UFW_DURACAO_CURTA inválida: ", err)
	}
	if b.duracaoLonga, err = parseDuracao(envOu("UFW_DURACAO_LONGA", "7d")); err != nil {
		log.Fatal("UFW_DURACAO_LONGA inválida: ", err)
	}
	go b.rotinaExpiracao()
	b.logAuth = envOu("UFW_AUTH_LOG", "/var/log/auth.log")
	if b.autoLimite, err = strconv.Atoi(envOu("UFW_AUTO_LIMITE", "20")); err != nil || b.autoLimite < 0 {
		log.Fatal("UFW_AUTO_LIMITE inválido (use um número, 0 desliga)")
	}
	if b.autoJanela, err = parseDuracao(envOu("UFW_AUTO_JANELA", "10m")); err != nil {
		log.Fatal("UFW_AUTO_JANELA inválida: ", err)
	}
	envInt := func(nome, padrao string) int {
		n, err := strconv.Atoi(envOu(nome, padrao))
		if err != nil || n < 0 {
			log.Fatalf("%s inválido (use um número, 0 desliga)", nome)
		}
		return n
	}
	b.alertaPico = envInt("UFW_ALERTA_PICO", "100")
	b.alertaPortas = envInt("UFW_ALERTA_PORTAS", "15")
	b.alertaMaxHora = envInt("UFW_ALERTA_MAX_HORA", "20")
	b.alertasSSH = envOu("UFW_ALERTA_SSH", "1") != "0"
	if b.alertaJanela, err = parseDuracao(envOu("UFW_ALERTA_JANELA", "5m")); err != nil {
		log.Fatal("UFW_ALERTA_JANELA inválida: ", err)
	}
	if b.alertaPausa, err = parseDuracao(envOu("UFW_ALERTA_PAUSA", "30m")); err != nil {
		log.Fatal("UFW_ALERTA_PAUSA inválida: ", err)
	}
	b.arquivoSSH = envOu("UFW_SSH_CONHECIDOS", filepath.Join(filepath.Dir(b.arquivoPendentes), "ssh_conhecidos.json"))
	if b.autoLimite > 0 || b.alertaPico > 0 || b.alertaPortas > 0 || b.alertasSSH {
		go b.rotinaVarredura()
		log.Printf("varredura dos logs ligada (ban automático: >%d em %s)", b.autoLimite, b.autoJanela)
	}
	if b.mon, err = novoMonitor(b); err != nil {
		log.Fatal(err)
	}
	if b.mon != nil {
		go b.mon.rodar()
	}
	b.relatorio = b.rodarRelatorio(envOu("UFW_RELATORIO_BIN", "./ufwrelatorio"))
	for _, ip := range strings.Split(os.Getenv("UFW_NUNCA_BANIR"), ",") {
		if ip = strings.TrimSpace(ip); ip != "" {
			b.nuncaBanir[ip] = true
		}
	}
	b.registrarMenu()
	log.Println("ufwbot escutando respostas do Telegram...")
	b.laco()
}

func envOu(k, padrao string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return padrao
}

// laco faz "long polling": o Telegram segura a requisição até até 30s esperando um clique.
func (b *Bot) laco() {
	offset := 0
	for {
		var resp struct {
			OK     bool     `json:"ok"`
			Result []Update `json:"result"`
		}
		err := b.chamar("getUpdates", url.Values{
			"offset":          {strconv.Itoa(offset)},
			"timeout":         {"30"},
			"allowed_updates": {`["callback_query","message"]`},
		}, &resp)
		if err != nil {
			log.Println("erro:", err)
			time.Sleep(5 * time.Second)
			continue
		}
		for _, u := range resp.Result {
			offset = u.UpdateID + 1
			b.processar(u)
		}
	}
}

// processar trata um clique de botão.
func (b *Bot) processar(u Update) {
	if u.Message != nil {
		b.comando(u.Message)
		return
	}
	cq := u.CallbackQuery
	if cq == nil || cq.Message == nil {
		return
	}
	// TRAVA 1: só o seu chat. Qualquer outro clique é ignorado em silêncio.
	if cq.From.ID != b.chatAutorizado || cq.Message.Chat.ID != b.chatAutorizado {
		log.Printf("clique ignorado de usuário não autorizado (%d)", cq.From.ID)
		return
	}
	acao, id, ok := strings.Cut(cq.Data, ":")
	if acao == "menu" && ok {
		b.atalho(cq, id)
		return
	}
	if acao == "painel" && ok {
		b.responder(cq, "")
		b.editarPainel(cq)
		return
	}
	if acao == "desfazer" && ok {
		b.desfazer(cq, id)
		return
	}
	duracao, valida := b.duracaoDaAcao(acao)
	if !ok || !valida {
		b.responder(cq, "Ação desconhecida.")
		return
	}

	p, err := b.lerPendentes()
	// TRAVA 2: o clique precisa ser da lista atual, e ainda não usada.
	switch {
	case err != nil:
		b.responder(cq, "Não consegui ler a lista de pendentes.")
		return
	case p.ID != id:
		b.responder(cq, "Esta lista expirou (há um relatório mais novo).")
		b.tirarBotoes(cq)
		return
	case p.Processado:
		b.responder(cq, "Esta lista já foi respondida.")
		b.tirarBotoes(cq)
		return
	}
	// Marca como usada ANTES de agir: um clique duplo não bane duas vezes.
	p.Processado = true
	if err := b.salvarPendentes(p); err != nil {
		b.responder(cq, "Erro ao registrar a resposta; nada foi banido.")
		return
	}
	b.tirarBotoes(cq)

	if acao == "banir_nao" {
		b.responder(cq, "Ok, nenhum IP foi banido.")
		b.mensagem("Ok, nenhum IP foi banido.")
		return
	}

	var banidos, pulados, falhas []string
	for _, ip := range p.IPs {
		if motivo := b.protegido(ip); motivo != "" {
			pulados = append(pulados, ip+" ("+motivo+")")
			continue
		}
		if err := b.banir(ip); err != nil {
			falhas = append(falhas, ip)
			log.Printf("falha ao banir %s: %v", ip, err)
			continue
		}
		banidos = append(banidos, ip)
		b.registrarBan(ip, duracao)
	}
	b.responder(cq, fmt.Sprintf("%d IP(s) banido(s).", len(banidos)))

	// ✅ só quando tudo que era para banir foi banido; ⚠️ se algo falhou ou nada foi banido.
	icone, titulo := "✅", fmt.Sprintf("%d IP(s) banido(s) com sucesso", len(banidos))
	if len(falhas) > 0 || len(banidos) == 0 {
		icone, titulo = "⚠️", fmt.Sprintf("%d IP(s) banido(s)", len(banidos))
	}
	msg := icone + " " + titulo + "\nDuração: " + descreverDuracao(duracao)
	if len(banidos) > 0 {
		msg += "\n" + strings.Join(banidos, "\n")
	}
	if len(pulados) > 0 {
		msg += "\n\nIgnorados: " + strings.Join(pulados, ", ")
	}
	if len(falhas) > 0 {
		msg += "\n\nFalharam: " + strings.Join(falhas, ", ")
	}
	b.mensagem(msg)
}

// protegido devolve o motivo de um IP não dever ser banido ("" se pode).
func (b *Bot) protegido(ip string) string {
	addr := net.ParseIP(ip)
	switch {
	case addr == nil:
		return "IP inválido"
	case addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsUnspecified():
		return "endereço local/privado"
	case b.nuncaBanir[ip]:
		return "na lista UFW_NUNCA_BANIR"
	}
	return ""
}

// banirNoUfw insere a regra no TOPO (posição 1). O IP já foi validado por net.ParseIP e
// é passado como argumento separado, sem shell, então não há injeção de comando.
func banirNoUfw(ip string) error {
	out, err := exec.Command("ufw", "insert", "1", "deny", "from", ip).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (b *Bot) lerPendentes() (Pendentes, error) {
	var p Pendentes
	dados, err := os.ReadFile(b.arquivoPendentes)
	if err != nil {
		return p, err
	}
	return p, json.Unmarshal(dados, &p)
}

func (b *Bot) salvarPendentes(p Pendentes) error {
	dados, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(b.arquivoPendentes, dados, 0o600)
}

// ---- chamadas à API do Telegram ----

func (b *Bot) responder(cq *CallbackQuery, texto string) {
	b.chamar("answerCallbackQuery", url.Values{"callback_query_id": {cq.ID}, "text": {texto}}, nil)
}

func (b *Bot) tirarBotoes(cq *CallbackQuery) {
	b.chamar("editMessageReplyMarkup", url.Values{
		"chat_id":      {strconv.FormatInt(cq.Message.Chat.ID, 10)},
		"message_id":   {strconv.Itoa(cq.Message.MessageID)},
		"reply_markup": {`{"inline_keyboard":[]}`},
	}, nil)
}

func (b *Bot) mensagem(texto string) {
	b.chamar("sendMessage", url.Values{"chat_id": {strconv.FormatInt(b.chatAutorizado, 10)}, "text": {texto}}, nil)
}

func (b *Bot) chamar(metodo string, params url.Values, destino any) error {
	resp, err := b.cli.PostForm(fmt.Sprintf("%s/bot%s/%s", b.api, b.token, metodo), params)
	if err != nil {
		return fmt.Errorf("falha de rede em %s", metodo) // o erro bruto conteria o token na URL
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s respondeu %d", metodo, resp.StatusCode)
	}
	if destino != nil {
		return json.NewDecoder(resp.Body).Decode(destino)
	}
	return nil
}
