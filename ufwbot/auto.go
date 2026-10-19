package main

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var reFalhaSSH = regexp.MustCompile(`Failed \S+ for (?:invalid user )?\S+ from (\S+)`)

// ipDaTentativa devolve o IP de uma linha de log que conta como tentativa hostil:
// um "[UFW BLOCK]" (campo SRC=) ou uma falha de login no SSH. "" para as demais linhas.
func ipDaTentativa(l string) string {
	if strings.Contains(l, "[UFW BLOCK]") {
		for _, par := range strings.Fields(l) {
			if ip, ok := strings.CutPrefix(par, "SRC="); ok {
				return ip
			}
		}
		return ""
	}
	if m := reFalhaSSH.FindStringSubmatch(l); m != nil {
		return m[1]
	}
	return ""
}

// contarTentativa registra uma tentativa do IP e devolve true quando ele passou do limite
// dentro da janela. Só a rotina de varredura chama isto (um único goroutine).
func (b *Bot) contarTentativa(ip string, agora time.Time) bool {
	if b.janelas == nil {
		b.janelas = map[string][]time.Time{}
	}
	corte := agora.Add(-b.autoJanela)
	l := b.janelas[ip]
	i := 0
	for i < len(l) && !l[i].After(corte) {
		i++
	}
	l = append(l[i:], agora)
	b.janelas[ip] = l
	return len(l) > b.autoLimite
}

// varrerLinhas conta as tentativas das linhas e bane sozinho quem passar do limite.
func (b *Bot) varrerLinhas(linhas []string, agora time.Time) {
	for _, l := range linhas {
		if b.alertasSSH {
			if user, ip := loginAceito(l); ip != "" {
				b.loginSSH(user, ip, agora)
				continue
			}
		}
		ip := ipDaTentativa(l)
		if ip == "" || net.ParseIP(ip) == nil {
			continue
		}
		b.registrarEvento(ip, portaDaLinha(l), agora)
		if b.autoLimite > 0 && b.contarTentativa(ip, agora) {
			b.autoBanir(ip, len(b.janelas[ip]))
		}
	}
	// Não deixa o mapa crescer sem limite: descarta quem já saiu da janela.
	if len(b.janelas) > 10000 {
		for ip, l := range b.janelas {
			if len(l) == 0 || !l[len(l)-1].After(agora.Add(-b.autoJanela)) {
				delete(b.janelas, ip)
			}
		}
	}
}

// autoBanir bane o IP sem perguntar e avisa no Telegram com o botão "Desfazer".
// IPs protegidos, já banidos ou já tratados (inclusive os desfeitos pelo botão) são ignorados.
func (b *Bot) autoBanir(ip string, tentativas int) {
	b.muAuto.Lock()
	if b.tratados == nil {
		b.tratados = map[string]bool{}
	}
	if b.tratados[ip] {
		b.muAuto.Unlock()
		return
	}
	b.tratados[ip] = true
	b.muAuto.Unlock()

	if motivo := b.protegido(ip); motivo != "" {
		return // fica para o relatório, que pede confirmação (ou nunca bane, se protegido)
	}
	if saida, err := b.ufw("status"); err == nil && contem(ipsBanidos(saida), ip) {
		return
	}
	if err := b.banir(ip); err != nil {
		log.Printf("falha no ban automático de %s: %v", ip, err)
		b.muAuto.Lock()
		delete(b.tratados, ip) // tenta de novo na próxima tentativa
		b.muAuto.Unlock()
		b.mensagem("⚠️ Falha no ban automático de " + ip)
		return
	}
	b.registrarBan(ip, b.duracaoCurta)
	texto := fmt.Sprintf("🤖 Ban automático: %s\n%d tentativas em %s\nDuração: %s",
		ip, tentativas, descreverDuracao(b.autoJanela), descreverDuracao(b.duracaoCurta))
	b.mensagemComBotoes(texto, `{"inline_keyboard":[[{"text":"↩️ Desfazer","callback_data":"desfazer:`+ip+`"}]]}`)
}

// desfazer trata o botão "Desfazer": remove o ban e impede novo ban automático deste IP
// até o bot reiniciar.
func (b *Bot) desfazer(cq *CallbackQuery, ip string) {
	addr := net.ParseIP(ip)
	if addr == nil {
		b.responder(cq, "IP inválido.")
		return
	}
	ip = addr.String()
	b.muAuto.Lock()
	if b.tratados == nil {
		b.tratados = map[string]bool{}
	}
	b.tratados[ip] = true
	b.muAuto.Unlock()
	b.tirarBotoes(cq)
	if saida, err := b.ufw("status"); err == nil && !contem(ipsBanidos(saida), ip) {
		b.esquecerBan(ip)
		b.responder(cq, ip+" já não estava banido.")
		return
	}
	if _, err := b.ufw("delete", "deny", "from", ip); err != nil {
		log.Printf("falha ao desfazer %s: %v", ip, err)
		b.responder(cq, "Falha ao desbanir.")
		return
	}
	b.esquecerBan(ip)
	b.responder(cq, ip+" desbanido.")
	b.mensagem("↩️ " + ip + " desbanido; não será banido automaticamente de novo.")
}

// esquecerTratado libera o IP para novo ban automático (chamado quando o ban expira).
func (b *Bot) esquecerTratado(ip string) {
	b.muAuto.Lock()
	delete(b.tratados, ip)
	b.muAuto.Unlock()
}

// novasLinhas devolve as linhas completas gravadas em "caminho" desde a última leitura.
// Na primeira vez só guarda o tamanho atual (não reprocessa o histórico). Se o arquivo
// encolheu (rotação do log), recomeça do início.
func (b *Bot) novasLinhas(caminho string) []string {
	if b.offsets == nil {
		b.offsets = map[string]int64{}
	}
	f, err := os.Open(caminho)
	if err != nil {
		return nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil
	}
	ant, visto := b.offsets[caminho]
	switch {
	case !visto:
		b.offsets[caminho] = st.Size()
		return nil
	case st.Size() < ant:
		ant = 0
	case st.Size() == ant:
		return nil
	}
	buf := make([]byte, min(st.Size()-ant, 8<<20)) // no máximo 8 MB por rodada
	n, _ := f.ReadAt(buf, ant)
	buf = buf[:n]
	fim := strings.LastIndexByte(string(buf), '\n')
	if fim < 0 {
		if len(buf) < 8<<20 {
			return nil // linha ainda incompleta: espera a próxima rodada
		}
		fim = len(buf) - 1 // linha absurdamente longa: descarta
	}
	b.offsets[caminho] = ant + int64(fim) + 1
	return strings.Split(strings.TrimRight(string(buf[:fim+1]), "\n"), "\n")
}

// rotinaVarredura lê os logs a cada 15 segundos: ban automático e alertas.
func (b *Bot) rotinaVarredura() {
	if b.alertasSSH {
		var hist []string
		for _, c := range []string{b.logAuth + ".1", b.logAuth} {
			if dados, err := os.ReadFile(c); err == nil {
				hist = append(hist, strings.Split(string(dados), "\n")...)
			}
		}
		b.carregarConhecidos(hist)
	}
	for {
		for _, c := range []string{b.logUfw, b.logAuth} {
			b.varrerLinhas(b.novasLinhas(c), b.now())
		}
		time.Sleep(15 * time.Second)
	}
}

func (b *Bot) mensagemComBotoes(texto, teclado string) {
	b.chamar("sendMessage", url.Values{
		"chat_id":      {strconv.FormatInt(b.chatAutorizado, 10)},
		"text":         {texto},
		"reply_markup": {teclado},
	}, nil)
}
