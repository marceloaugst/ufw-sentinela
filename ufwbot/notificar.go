package main

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

const tecladoPainel = `{"inline_keyboard":[[{"text":"🔄 Atualizar","callback_data":"painel:atualizar"}]]}`

func (b *Bot) cmdPainel() {
	if b.mon == nil {
		b.mensagem("Monitor desligado (MON_INTERVALO=0).")
		return
	}
	b.mensagemComBotoes(b.mon.painel(), tecladoPainel)
}

// editarPainel troca o texto da própria mensagem (botão "Atualizar"), sem encher o chat.
func (b *Bot) editarPainel(cq *CallbackQuery) {
	if b.mon == nil {
		return
	}
	b.chamar("editMessageText", url.Values{
		"chat_id":      {strconv.FormatInt(cq.Message.Chat.ID, 10)},
		"message_id":   {strconv.Itoa(cq.Message.MessageID)},
		"text":         {b.mon.painel()},
		"reply_markup": {tecladoPainel},
	}, nil)
}

const usoCLI = `uso:
  ufwbot deploy <app> <ok|falha> [detalhe...]   avisa um deploy no Telegram
  ufwbot notificar <texto...>                   envia uma mensagem qualquer
(sem argumentos, o ufwbot roda como bot)`

// subcomando trata os subcomandos usados por scripts de deploy. Devolve o código de saída.
func (b *Bot) subcomando(args []string) int {
	host, _ := os.Hostname()
	var texto string
	switch args[0] {
	case "deploy":
		if len(args) < 3 || (args[2] != "ok" && args[2] != "falha") {
			fmt.Fprintln(os.Stderr, usoCLI)
			return 2
		}
		ic, verbo := "🚀", "concluído"
		if args[2] == "falha" {
			ic, verbo = "❌", "FALHOU"
		}
		texto = fmt.Sprintf("%s Deploy de %s %s em %s", ic, args[1], verbo, host)
		if len(args) > 3 {
			texto += "\n" + strings.Join(args[3:], " ")
		}
	case "notificar":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, usoCLI)
			return 2
		}
		texto = strings.Join(args[1:], " ")
	default:
		fmt.Fprintln(os.Stderr, usoCLI)
		return 2
	}
	err := b.chamar("sendMessage", url.Values{"chat_id": {strconv.FormatInt(b.chatAutorizado, 10)}, "text": {texto}}, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "erro:", err)
		return 1
	}
	return 0
}
