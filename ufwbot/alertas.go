package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

var reLoginOk = regexp.MustCompile(`Accepted \S+ for (\S+) from (\S+)`)

// loginAceito devolve usuário e IP de um login SSH bem-sucedido ("" se a linha não for um).
func loginAceito(l string) (user, ip string) {
	if m := reLoginOk.FindStringSubmatch(l); m != nil {
		return m[1], m[2]
	}
	return "", ""
}

// portaDaLinha devolve o DPT= de um "[UFW BLOCK]" ("" se não houver).
func portaDaLinha(l string) string {
	if !strings.Contains(l, "[UFW BLOCK]") {
		return ""
	}
	for _, par := range strings.Fields(l) {
		if p, ok := strings.CutPrefix(par, "DPT="); ok {
			return p
		}
	}
	return ""
}

type tentativa struct {
	t     time.Time
	ip    string
	porta string
}

// registrarEvento guarda a tentativa e dispara os alertas de pico e de varredura de portas.
// Roda só na rotina de varredura (um goroutine), por isso não usa trava.
func (b *Bot) registrarEvento(ip, porta string, agora time.Time) {
	if b.alertaPico <= 0 && b.alertaPortas <= 0 {
		return
	}
	corte := agora.Add(-b.alertaJanela)
	i := 0
	for i < len(b.eventos) && !b.eventos[i].t.After(corte) {
		i++
	}
	b.eventos = append(b.eventos[i:], tentativa{agora, ip, porta})

	if b.alertaPortas > 0 && porta != "" {
		portas := map[string]bool{}
		for _, e := range b.eventos {
			if e.ip == ip && e.porta != "" {
				portas[e.porta] = true
			}
		}
		if len(portas) >= b.alertaPortas {
			b.avisar("scan:"+ip, agora, fmt.Sprintf("🔎 Varredura de portas: %s tocou em %d portas diferentes em %s",
				ip, len(portas), descreverDuracao(b.alertaJanela)))
		}
	}
	if b.alertaPico > 0 && len(b.eventos) >= b.alertaPico {
		cont := map[string]int{}
		for _, e := range b.eventos {
			cont[e.ip]++
		}
		type par struct {
			ip string
			n  int
		}
		var top []par
		for k, n := range cont {
			top = append(top, par{k, n})
		}
		sort.Slice(top, func(i, j int) bool {
			if top[i].n != top[j].n {
				return top[i].n > top[j].n
			}
			return top[i].ip < top[j].ip
		})
		msg := fmt.Sprintf("📈 Pico de tentativas: %d em %s, de %d IP(s). Mais ativos:", len(b.eventos), descreverDuracao(b.alertaJanela), len(top))
		for _, p := range top[:min(3, len(top))] {
			msg += fmt.Sprintf("\n• %s — %d", p.ip, p.n)
		}
		b.avisar("pico", agora, msg)
	}
}

// loginSSH avisa sobre login bem-sucedido de um IP nunca visto. O IP passa a ser conhecido.
// IPs da UFW_NUNCA_BANIR (os seus) são de confiança e não geram aviso.
func (b *Bot) loginSSH(user, ip string, agora time.Time) {
	if b.conhecidos == nil {
		b.conhecidos = map[string]time.Time{}
	}
	if net.ParseIP(ip) == nil {
		return
	}
	if _, ok := b.conhecidos[ip]; ok {
		return
	}
	b.conhecidos[ip] = agora
	b.salvarConhecidos()
	if b.nuncaBanir[ip] {
		return
	}
	b.avisar("ssh:"+ip, agora, fmt.Sprintf("🔑 Login SSH de IP novo: %s entrou como %s", ip, user))
}

// carregarConhecidos lê os IPs já vistos. Se o arquivo ainda não existe, aprende com o
// histórico do auth.log (sem avisar), para o primeiro uso não gerar uma enxurrada de alertas.
func (b *Bot) carregarConhecidos(historico []string) {
	b.conhecidos = map[string]time.Time{}
	if b.arquivoSSH == "" {
		return
	}
	if dados, err := os.ReadFile(b.arquivoSSH); err == nil {
		json.Unmarshal(dados, &b.conhecidos)
		return
	}
	for _, l := range historico {
		if _, ip := loginAceito(l); net.ParseIP(ip) != nil {
			b.conhecidos[ip] = b.now()
		}
	}
	b.salvarConhecidos()
}

func (b *Bot) salvarConhecidos() {
	if b.arquivoSSH == "" {
		return
	}
	dados, err := json.MarshalIndent(b.conhecidos, "", "  ")
	if err == nil {
		tmp := b.arquivoSSH + ".tmp"
		if err = os.WriteFile(tmp, dados, 0o600); err == nil {
			err = os.Rename(tmp, b.arquivoSSH)
		}
	}
	if err != nil {
		log.Printf("não consegui gravar %s: %v", b.arquivoSSH, err)
	}
}

// avisar manda o alerta, respeitando a pausa por tipo/IP e o máximo de alertas por hora.
func (b *Bot) avisar(chave string, agora time.Time, texto string) {
	if b.ultimoAlerta == nil {
		b.ultimoAlerta = map[string]time.Time{}
	}
	if t, ok := b.ultimoAlerta[chave]; ok && agora.Sub(t) < b.alertaPausa {
		return
	}
	i := 0
	for i < len(b.enviados) && agora.Sub(b.enviados[i]) >= time.Hour {
		i++
	}
	b.enviados = b.enviados[i:]
	if b.alertaMaxHora > 0 && len(b.enviados) >= b.alertaMaxHora {
		if !b.avisouLimite {
			b.avisouLimite = true
			b.mensagem(fmt.Sprintf("🔇 Já foram %d alertas na última hora; os próximos serão suprimidos até a frequência baixar.", b.alertaMaxHora))
		}
		return
	}
	b.avisouLimite = false
	b.ultimoAlerta[chave] = agora
	b.enviados = append(b.enviados, agora)
	if len(b.ultimoAlerta) > 5000 { // limpeza das pausas já vencidas
		for k, t := range b.ultimoAlerta {
			if agora.Sub(t) >= b.alertaPausa {
				delete(b.ultimoAlerta, k)
			}
		}
	}
	b.mensagem(texto)
}
