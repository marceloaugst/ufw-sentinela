package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func alertaBot(t *testing.T) (*Bot, *time.Time, *[]string) {
	b, _, _ := autoBot(t)
	agora := time.Date(2026, 10, 19, 12, 0, 0, 0, time.Local)
	b.agora = func() time.Time { return agora }
	b.autoLimite = 0 // aqui só os alertas
	b.alertaJanela, b.alertaPausa, b.alertaMaxHora = 5*time.Minute, 30*time.Minute, 20
	var msgs []string
	// Captura as mensagens sem depender do servidor falso.
	return b, &agora, &msgs
}

func bloqueioPorta(ip string, porta int) string {
	return fmt.Sprintf("2026-10-19T12:00:00-03:00 h kernel: [UFW BLOCK] IN=eth0 SRC=%s DST=1.1.1.1 PROTO=TCP DPT=%d", ip, porta)
}

func TestAlertaVarreduraDePortas(t *testing.T) {
	b, agora, _ := alertaBot(t)
	b.alertaPortas = 5
	for p := 1; p <= 4; p++ {
		b.varrerLinhas([]string{bloqueioPorta("192.0.2.70", p)}, *agora)
	}
	if ultimaMensagem != "" {
		t.Fatalf("alertou cedo: %q", ultimaMensagem)
	}
	b.varrerLinhas([]string{bloqueioPorta("192.0.2.70", 5), bloqueioPorta("192.0.2.70", 5)}, *agora)
	if !strings.Contains(ultimaMensagem, "Varredura de portas: 192.0.2.70 tocou em 5 portas") {
		t.Fatalf("alerta: %q", ultimaMensagem)
	}
	// Mesma porta repetida não conta como varredura.
	ultimaMensagem = ""
	for i := 0; i < 20; i++ {
		b.varrerLinhas([]string{bloqueioPorta("192.0.2.71", 22)}, *agora)
	}
	if ultimaMensagem != "" {
		t.Fatalf("porta repetida alertou: %q", ultimaMensagem)
	}
}

func TestAlertaPicoEPausa(t *testing.T) {
	b, agora, _ := alertaBot(t)
	b.alertaPico = 10
	b.varrerLinhas(rajada("192.0.2.80", 9), *agora)
	if ultimaMensagem != "" {
		t.Fatal("alertou cedo")
	}
	b.varrerLinhas(rajada("192.0.2.81", 3), *agora)
	if !strings.Contains(ultimaMensagem, "Pico de tentativas: 10 em 5m") || !strings.Contains(ultimaMensagem, "• 192.0.2.80 — 9") {
		t.Fatalf("pico: %q", ultimaMensagem)
	}
	// Dentro da pausa não repete; depois dela volta a avisar.
	ultimaMensagem = ""
	b.varrerLinhas(rajada("192.0.2.80", 30), *agora)
	if ultimaMensagem != "" {
		t.Fatalf("repetiu dentro da pausa: %q", ultimaMensagem)
	}
	*agora = agora.Add(31 * time.Minute)
	b.varrerLinhas(rajada("192.0.2.80", 12), *agora)
	if !strings.Contains(ultimaMensagem, "Pico") {
		t.Fatal("deveria alertar de novo após a pausa")
	}
}

func TestAlertaLoginSshIpNovo(t *testing.T) {
	b, agora, _ := alertaBot(t)
	b.alertasSSH = true
	b.arquivoSSH = filepath.Join(t.TempDir(), "ssh.json")
	b.nuncaBanir["192.0.2.1"] = true
	auth := filepath.Join(t.TempDir(), "auth.log")
	os.WriteFile(auth, []byte("Oct 1 h sshd[1]: Accepted publickey for marcelo from 198.51.100.9 port 5 ssh2\n"), 0o600)
	hist, _ := os.ReadFile(auth)
	b.carregarConhecidos(strings.Split(string(hist), "\n"))

	login := func(user, ip string) string {
		return "Oct 19 12:00:00 h sshd[2]: Accepted password for " + user + " from " + ip + " port 22 ssh2"
	}
	b.varrerLinhas([]string{login("marcelo", "198.51.100.9")}, *agora) // conhecido
	b.varrerLinhas([]string{login("marcelo", "192.0.2.1")}, *agora)    // seu IP
	if ultimaMensagem != "" {
		t.Fatalf("não deveria alertar: %q", ultimaMensagem)
	}
	b.varrerLinhas([]string{login("root", "203.0.113.77")}, *agora)
	if ultimaMensagem != "🔑 Login SSH de IP novo: 203.0.113.77 entrou como root" {
		t.Fatalf("alerta: %q", ultimaMensagem)
	}
	// Só avisa uma vez e o IP fica gravado.
	ultimaMensagem = ""
	b.varrerLinhas([]string{login("root", "203.0.113.77")}, *agora)
	if ultimaMensagem != "" {
		t.Fatal("avisou duas vezes")
	}
	b2 := &Bot{arquivoSSH: b.arquivoSSH, agora: b.agora}
	b2.carregarConhecidos(nil)
	if _, ok := b2.conhecidos["203.0.113.77"]; !ok || len(b2.conhecidos) != 3 {
		t.Fatalf("persistência: %v", b2.conhecidos)
	}
}

func TestAlertaLimiteDeAlertasPorHora(t *testing.T) {
	b, agora, _ := alertaBot(t)
	b.alertaPortas, b.alertaMaxHora = 2, 3
	enviadas := 0
	for i := 0; i < 6; i++ {
		ip := fmt.Sprintf("192.0.2.%d", 100+i)
		ultimaMensagem = ""
		b.varrerLinhas([]string{bloqueioPorta(ip, 1), bloqueioPorta(ip, 2)}, *agora)
		if strings.Contains(ultimaMensagem, "Varredura") {
			enviadas++
		}
		if i == 3 && !strings.Contains(ultimaMensagem, "suprimidos") {
			t.Fatalf("faltou o aviso de supressão: %q", ultimaMensagem)
		}
	}
	if enviadas != 3 {
		t.Fatalf("enviadas=%d, esperava 3", enviadas)
	}
	*agora = agora.Add(61 * time.Minute)
	ultimaMensagem = ""
	b.varrerLinhas([]string{bloqueioPorta("192.0.2.200", 1), bloqueioPorta("192.0.2.200", 2)}, *agora)
	if !strings.Contains(ultimaMensagem, "Varredura") {
		t.Fatal("deveria voltar a alertar após uma hora")
	}
}
