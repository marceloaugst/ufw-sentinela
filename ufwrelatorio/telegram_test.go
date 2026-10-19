package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestEnviarTelegram(t *testing.T) {
	var caminho, chat, legenda, nomeArq, conteudo string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caminho = r.URL.Path
		r.ParseMultipartForm(1 << 20)
		chat, legenda = r.FormValue("chat_id"), r.FormValue("caption")
		f, h, err := r.FormFile("document")
		if err == nil {
			nomeArq = h.Filename
			b, _ := io.ReadAll(f)
			conteudo = string(b)
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	tmp := t.TempDir() + "/rel.xlsx"
	os.WriteFile(tmp, []byte("DADOS"), 0o644)

	if err := enviarTelegram(srv.URL, "TOKEN123", "42", tmp, "oi", `{"inline_keyboard":[]}`); err != nil {
		t.Fatal(err)
	}
	if caminho != "/botTOKEN123/sendDocument" || chat != "42" || legenda != "oi" || nomeArq != "rel.xlsx" || conteudo != "DADOS" {
		t.Fatalf("requisição inesperada: %q %q %q %q %q", caminho, chat, legenda, nomeArq, conteudo)
	}

	// Erro HTTP deve virar erro Go.
	ruim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "chat not found", 400)
	}))
	defer ruim.Close()
	err := enviarTelegram(ruim.URL, "T", "1", tmp, "", "")
	if err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("esperava erro 400, veio %v", err)
	}
}
