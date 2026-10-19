package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func linhaBloqueio(ip string) string {
	return "2026-10-19T12:00:00-03:00 h kernel: [UFW BLOCK] IN=eth0 SRC=" + ip + " DST=1.1.1.1 PROTO=TCP DPT=22"
}

func autoBot(t *testing.T) (*Bot, *[]string, *time.Time) {
	b, _, banidos := novoBot(t)
	agora := time.Date(2026, 10, 19, 12, 0, 0, 0, time.Local)
	b.agora = func() time.Time { return agora }
	b.autoLimite, b.autoJanela = 5, 10*time.Minute
	var ch [][]string
	comUfw(b, &ch)
	return b, banidos, &agora
}

func rajada(ip string, n int) []string {
	var l []string
	for i := 0; i < n; i++ {
		l = append(l, linhaBloqueio(ip))
	}
	return l
}

func TestAutoBanPassouDoLimite(t *testing.T) {
	b, banidos, agora := autoBot(t)
	b.varrerLinhas(rajada("192.0.2.60", 5), *agora) // 5 não passa de "mais de 5"
	if len(*banidos) != 0 {
		t.Fatalf("baniu cedo: %v", *banidos)
	}
	b.varrerLinhas(rajada("192.0.2.60", 20), *agora) // continua tentando
	if len(*banidos) != 1 || (*banidos)[0] != "192.0.2.60" {
		t.Fatalf("deveria banir uma vez: %v", *banidos)
	}
	if !strings.Contains(ultimaMensagem, "Ban automático: 192.0.2.60") || !strings.Contains(ultimoTeclado, "desfazer:192.0.2.60") {
		t.Fatalf("aviso errado: %q %q", ultimaMensagem, ultimoTeclado)
	}
	if x, ok := b.lerBans()["192.0.2.60"]; !ok || !x.Expira.Equal(agora.Add(24*time.Hour)) {
		t.Fatalf("ban temporário não registrado: %+v", b.lerBans())
	}
}

func TestAutoBanSshEJanela(t *testing.T) {
	b, banidos, agora := autoBot(t)
	ssh := "Oct 19 12:00:00 h sshd[1]: Failed password for invalid user admin from 192.0.2.61 port 22 ssh2"
	for i := 0; i < 5; i++ {
		b.varrerLinhas([]string{ssh}, *agora)
		*agora = agora.Add(3 * time.Minute) // tentativas lentas: nunca 6 dentro de 10 min
	}
	if len(*banidos) != 0 {
		t.Fatalf("janela não descartou antigas: %v", *banidos)
	}
	b.varrerLinhas(rajada("192.0.2.61", 6), *agora)
	if len(*banidos) != 1 {
		t.Fatalf("SSH + UFW deveriam somar: %v", *banidos)
	}
}

func TestAutoBanIgnoraProtegidosEJaBanidos(t *testing.T) {
	b, banidos, agora := autoBot(t)
	b.varrerLinhas(rajada("8.8.4.4", 10), *agora)     // nuncaBanir
	b.varrerLinhas(rajada("10.0.0.7", 10), *agora)    // privado
	b.varrerLinhas(rajada("203.0.113.5", 10), *agora) // já tem regra no ufw (saidaUfw)
	b.varrerLinhas([]string{"lixo", linhaBloqueio("naoeip")}, *agora)
	if len(*banidos) != 0 {
		t.Fatalf("não deveria banir: %v", *banidos)
	}
}

func TestDesfazerAutoBan(t *testing.T) {
	b, banidos, agora := autoBot(t)
	var ch [][]string
	comUfw(b, &ch)
	b.varrerLinhas(rajada("192.0.2.50", 6), *agora)
	b.registrarBan("203.0.113.5", 0)
	b.processar(clique(999, 999, "desfazer:203.0.113.5")) // não autorizado
	if len(b.lerBans()) == 0 {
		t.Fatal("não autorizado desfez")
	}
	ch = nil
	b.processar(clique(42, 42, "desfazer:203.0.113.5"))
	if len(ch) != 2 || strings.Join(ch[1], " ") != "delete deny from 203.0.113.5" {
		t.Fatalf("chamadas: %v", ch)
	}
	if _, ok := b.lerBans()["203.0.113.5"]; ok {
		t.Fatal("registro deveria sumir")
	}
	// Depois de desfeito, não é banido sozinho de novo.
	n := len(*banidos)
	b.tratados["203.0.113.5"] = true
	b.varrerLinhas(rajada("203.0.113.5", 20), *agora)
	if len(*banidos) != n {
		t.Fatal("baniu de novo após desfazer")
	}
	b.processar(clique(42, 42, "desfazer:naoeip;reboot"))
	for _, c := range ch {
		if strings.Contains(strings.Join(c, " "), "reboot") {
			t.Fatal("IP inválido chegou ao ufw")
		}
	}
}

func TestNovasLinhas(t *testing.T) {
	b, _, _ := autoBot(t)
	arq := filepath.Join(t.TempDir(), "x.log")
	os.WriteFile(arq, []byte("antiga\n"), 0o600)
	if l := b.novasLinhas(arq); l != nil {
		t.Fatalf("histórico não deve ser relido: %v", l)
	}
	f, _ := os.OpenFile(arq, os.O_APPEND|os.O_WRONLY, 0)
	fmt.Fprint(f, "a\nb\nmeia")
	if l := b.novasLinhas(arq); strings.Join(l, ",") != "a,b" {
		t.Fatalf("linhas: %v", l)
	}
	fmt.Fprint(f, "-linha\n")
	f.Close()
	if l := b.novasLinhas(arq); strings.Join(l, ",") != "meia-linha" {
		t.Fatalf("linha incompleta: %v", l)
	}
	os.WriteFile(arq, []byte("nova\n"), 0o600) // rotação: arquivo menor
	if l := b.novasLinhas(arq); strings.Join(l, ",") != "nova" {
		t.Fatalf("rotação: %v", l)
	}
	if l := b.novasLinhas(arq + ".nao"); l != nil {
		t.Fatal("arquivo ausente")
	}
}
