package main

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// enviarTelegram manda um arquivo como documento para o chat, via Bot API (sendDocument).
// apiBase é "https://api.telegram.org" em produção (parâmetro só para permitir testes).
func enviarTelegram(apiBase, token, chatID, caminho, legenda, botoes string) error {
	return enviarArquivo(apiBase, token, chatID, caminho, legenda, botoes, "sendDocument", "document")
}

// enviarFoto manda uma imagem PNG como foto (sendPhoto).
func enviarFoto(apiBase, token, chatID, caminho, legenda string) error {
	return enviarArquivo(apiBase, token, chatID, caminho, legenda, "", "sendPhoto", "photo")
}

func enviarArquivo(apiBase, token, chatID, caminho, legenda, botoes, metodo, campo string) error {
	arquivo, err := os.Open(caminho)
	if err != nil {
		return err
	}
	defer arquivo.Close()

	// O corpo é multipart/form-data: campos de texto + o arquivo.
	var corpo bytes.Buffer
	mw := multipart.NewWriter(&corpo)
	mw.WriteField("chat_id", chatID)
	mw.WriteField("caption", legenda)
	if botoes != "" { // teclado inline (JSON) para o usuário responder com um toque
		mw.WriteField("reply_markup", botoes)
	}
	parte, err := mw.CreateFormFile(campo, filepath.Base(caminho))
	if err != nil {
		return err
	}
	if _, err := io.Copy(parte, arquivo); err != nil {
		return err
	}
	if err := mw.Close(); err != nil {
		return err
	}

	url := fmt.Sprintf("%s/bot%s/%s", apiBase, token, metodo)
	req, err := http.NewRequest(http.MethodPost, url, &corpo)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())

	cli := &http.Client{Timeout: 60 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		// A URL contém o token; não expomos o erro bruto do net/http.
		return fmt.Errorf("falha de rede ao falar com o Telegram")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		resposta, _ := io.ReadAll(io.LimitReader(resp.Body, 500))
		return fmt.Errorf("telegram respondeu %d: %s", resp.StatusCode, resposta)
	}
	return nil
}

// enviarMensagem manda um texto (com teclado inline opcional) via sendMessage.
func enviarMensagem(apiBase, token, chatID, texto, botoes string) error {
	v := url.Values{"chat_id": {chatID}, "text": {texto}}
	if botoes != "" {
		v.Set("reply_markup", botoes)
	}
	cli := &http.Client{Timeout: 30 * time.Second}
	resp, err := cli.PostForm(fmt.Sprintf("%s/bot%s/sendMessage", apiBase, token), v)
	if err != nil {
		return fmt.Errorf("falha de rede ao falar com o Telegram")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		resposta, _ := io.ReadAll(io.LimitReader(resp.Body, 500))
		return fmt.Errorf("telegram respondeu %d: %s", resp.StatusCode, resposta)
	}
	return nil
}
