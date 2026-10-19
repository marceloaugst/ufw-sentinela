package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var ultimaMensagem, ultimoTeclado string

func novoBot(t *testing.T) (*Bot, *[]string, *[]string) {
	var chamadas, banidos []string
	ultimaMensagem, ultimoTeclado = "", ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chamadas = append(chamadas, r.URL.Path)
		if strings.HasSuffix(r.URL.Path, "/sendMessage") {
			r.ParseForm()
			ultimaMensagem = r.Form.Get("text")
			ultimoTeclado = r.Form.Get("reply_markup")
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	arq := filepath.Join(t.TempDir(), "pendentes.json")
	b := &Bot{api: srv.URL, token: "T", chatAutorizado: 42, arquivoPendentes: arq,
		nuncaBanir: map[string]bool{"8.8.4.4": true}, cli: srv.Client(),
		arquivoBans: filepath.Join(filepath.Dir(arq), "bans.json"), duracaoCurta: 24 * time.Hour, duracaoLonga: 7 * 24 * time.Hour,
		banir: func(ip string) error { banidos = append(banidos, ip); return nil }}
	b.salvarPendentes(Pendentes{ID: "A1", IPs: []string{"203.0.113.5", "10.0.0.7", "8.8.4.4", "naoeip", "198.51.100.7"}})
	return b, &chamadas, &banidos
}

func clique(quem, chat int64, dados string) Update {
	cq := &CallbackQuery{ID: "cb", Data: dados}
	cq.From.ID = quem
	cq.Message = &struct {
		MessageID int                `json:"message_id"`
		Chat      struct{ ID int64 } `json:"chat"`
	}{MessageID: 7}
	cq.Message.Chat.ID = chat
	return Update{UpdateID: 1, CallbackQuery: cq}
}

func TestBanirSim(t *testing.T) {
	b, _, banidos := novoBot(t)
	b.processar(clique(42, 42, "banir_sim:A1"))
	if len(*banidos) != 2 || (*banidos)[0] != "203.0.113.5" || (*banidos)[1] != "198.51.100.7" {
		t.Fatalf("banidos errados: %v", *banidos) // privado, nuncaBanir e inválido ficam de fora
	}
	if !strings.HasPrefix(ultimaMensagem, "✅ 2 IP(s) banido(s) com sucesso") {
		t.Fatalf("mensagem de confirmação errada: %q", ultimaMensagem)
	}
	// Segundo clique na mesma lista não faz nada.
	b.processar(clique(42, 42, "banir_sim:A1"))
	if len(*banidos) != 2 {
		t.Fatalf("clique repetido baniu de novo: %v", *banidos)
	}
}

func TestNaoAutorizadoEListaAntiga(t *testing.T) {
	b, _, banidos := novoBot(t)
	b.processar(clique(999, 999, "banir_sim:A1")) // outra pessoa
	b.processar(clique(42, 999, "banir_sim:A1"))  // chat diferente
	b.processar(clique(42, 42, "banir_sim:ANTIGA"))
	if len(*banidos) != 0 {
		t.Fatalf("não deveria banir: %v", *banidos)
	}
	// A lista atual continua utilizável depois de tentativas inválidas.
	b.processar(clique(42, 42, "banir_nao:A1"))
	if len(*banidos) != 0 {
		t.Fatal("'Não' baniu algo")
	}
	if p, _ := b.lerPendentes(); !p.Processado {
		t.Fatal("lista deveria estar marcada como processada")
	}
	_ = os.Remove(b.arquivoPendentes)
}
