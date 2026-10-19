package main

import (
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func linhaUfw(h int, acao, ip string) []any {
	return []any{time.Date(2026, 10, 19, h, 30, 0, 0, time.Local), acao, "eth0", ip}
}

func TestGraficosHoraEPais(t *testing.T) {
	linhas := [][]any{
		linhaUfw(3, "BLOCK", "203.0.113.5"), linhaUfw(3, "BLOCK", "203.0.113.5"),
		linhaUfw(23, "BLOCK", "198.51.100.7"), linhaUfw(10, "ALLOW", "203.0.113.5"),
		{"", "BLOCK", "eth0", "192.0.2.1"},
	}
	h := bloqueiosPorHora(linhas)
	if h[3] != 2 || h[23] != 1 || h[10] != 0 {
		t.Fatalf("por hora: %v", h)
	}
	g := &Geo{cache: map[string]*InfoIP{
		"203.0.113.5": {Pais: "Brasil", Abuso: -1}, "198.51.100.7": {Pais: "Países Baixos", Abuso: -1},
	}}
	rot, val := bloqueiosPorPais(linhas, g)
	if strings.Join(rot, ",") != "Brasil,Desconhecido,Países Baixos" || val[0] != 2 || val[1] != 1 {
		// "Desconhecido" e "Países Baixos" empatam em 1: ordem alfabética
		t.Fatalf("por país: %v %v", rot, val)
	}

	pasta := t.TempDir()
	arqs, err := gerarGraficos(pasta, "x", "teste", linhas, g)
	if err != nil || len(arqs) != 2 {
		t.Fatalf("gráficos: %v %v", arqs, err)
	}
	for _, a := range arqs {
		f, _ := os.Open(a)
		img, err := png.Decode(f)
		f.Close()
		if err != nil || img.Bounds().Dx() != 900 {
			t.Fatalf("PNG inválido %s: %v", a, err)
		}
	}
	if arqs, _ := gerarGraficos(pasta, "y", "vazio", nil, g); arqs != nil {
		t.Fatal("sem dados não deve gerar gráfico")
	}
	if arqs, _ := gerarGraficos(pasta, "z", "semgeo", linhas, nil); len(arqs) != 1 {
		t.Fatalf("sem geo só gera o de horas: %v", arqs)
	}
}

func TestPassoEixo(t *testing.T) {
	for max, want := range map[int]int{1: 1, 5: 1, 12: 5, 100: 20, 1234: 500} {
		if got := passoEixo(max); got != want {
			t.Errorf("passoEixo(%d)=%d, esperava %d", max, got, want)
		}
	}
}

func TestEnviarFoto(t *testing.T) {
	var caminho, campo string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caminho = r.URL.Path
		r.ParseMultipartForm(1 << 20)
		if _, h, err := r.FormFile("photo"); err == nil {
			campo = h.Filename
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	arq := filepath.Join(t.TempDir(), "g.png")
	os.WriteFile(arq, []byte("PNG"), 0o600)
	if err := enviarFoto(srv.URL, "T", "42", arq, ""); err != nil {
		t.Fatal(err)
	}
	if caminho != "/botT/sendPhoto" || campo != "g.png" {
		t.Fatalf("requisição: %q %q", caminho, campo)
	}
}
