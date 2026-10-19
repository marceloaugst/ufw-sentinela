package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// Ban registra um ban feito pelo bot. Expira zero = permanente.
type Ban struct {
	Em     time.Time `json:"em"`
	Expira time.Time `json:"expira,omitzero"`
}

func (x Ban) descricao() string {
	if x.Expira.IsZero() {
		return "permanente"
	}
	return "expira " + x.Expira.Local().Format("02/01 15:04")
}

func (b *Bot) now() time.Time {
	if b.agora != nil {
		return b.agora()
	}
	return time.Now()
}

// parseDuracao aceita o formato do Go ("24h") e também dias ("7d").
func parseDuracao(s string) (time.Duration, error) {
	if dias, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(dias)
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("%q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%q", s)
	}
	return d, nil
}

func descreverDuracao(d time.Duration) string {
	switch {
	case d == 0:
		return "permanente"
	case d%(24*time.Hour) == 0:
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
	return d.String()
}

// duracaoDaAcao traduz o callback_data do botão. 0 = permanente. "banir_sim" é o botão antigo.
func (b *Bot) duracaoDaAcao(acao string) (time.Duration, bool) {
	switch acao {
	case "banir_24h":
		return b.duracaoCurta, true
	case "banir_7d":
		return b.duracaoLonga, true
	case "banir_perm", "banir_sim", "banir_nao":
		return 0, true
	}
	return 0, false
}

// lerBans lê bans.json (arquivo ausente ou ilegível = vazio). Quem chama com b.mu preso usa lerBansSemTrava.
func (b *Bot) lerBans() map[string]Ban {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lerBansSemTrava()
}

func (b *Bot) lerBansSemTrava() map[string]Ban {
	m := map[string]Ban{}
	if b.arquivoBans == "" {
		return m
	}
	if dados, err := os.ReadFile(b.arquivoBans); err == nil {
		json.Unmarshal(dados, &m)
	}
	return m
}

func (b *Bot) gravarBans(m map[string]Ban) error {
	if b.arquivoBans == "" {
		return nil
	}
	dados, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := b.arquivoBans + ".tmp"
	if err := os.WriteFile(tmp, dados, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, b.arquivoBans)
}

// registrarBan anota o ban; duracao 0 = permanente.
func (b *Bot) registrarBan(ip string, duracao time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	m := b.lerBansSemTrava()
	x := Ban{Em: b.now()}
	if duracao > 0 {
		x.Expira = x.Em.Add(duracao)
	}
	m[ip] = x
	if err := b.gravarBans(m); err != nil {
		log.Printf("não consegui registrar o ban de %s: %v", ip, err)
	}
}

func (b *Bot) esquecerBan(ip string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	m := b.lerBansSemTrava()
	if _, ok := m[ip]; ok {
		delete(m, ip)
		if err := b.gravarBans(m); err != nil {
			log.Printf("não consegui atualizar bans.json: %v", err)
		}
	}
}

// expirarVencidos remove do ufw os bans cuja data passou. Devolve os IPs desbanidos.
// Se o ufw falhar e a regra ainda existir, o IP fica para a próxima rodada; se a regra
// já não existe (alguém removeu à mão), apenas esquece o registro.
func (b *Bot) expirarVencidos() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	m := b.lerBansSemTrava()
	agora := b.now()
	var feitos []string
	for ip, x := range m {
		if x.Expira.IsZero() || x.Expira.After(agora) {
			continue
		}
		if _, err := b.ufw("delete", "deny", "from", ip); err != nil {
			saida, errSt := b.ufw("status")
			if errSt != nil || contem(ipsBanidos(saida), ip) {
				log.Printf("falha ao expirar o ban de %s: %v", ip, err)
				continue
			}
		}
		delete(m, ip)
		b.esquecerTratado(ip)
		feitos = append(feitos, ip)
	}
	if len(feitos) > 0 {
		if err := b.gravarBans(m); err != nil {
			log.Printf("não consegui atualizar bans.json: %v", err)
		}
	}
	return feitos
}

func contem(l []string, x string) bool {
	for _, v := range l {
		if v == x {
			return true
		}
	}
	return false
}

// rotinaExpiracao confere a cada minuto (e já na partida) se há bans vencidos.
func (b *Bot) rotinaExpiracao() {
	for {
		if feitos := b.expirarVencidos(); len(feitos) > 0 {
			b.mensagem("⏱ Ban expirado, IP(s) liberado(s):\n" + strings.Join(feitos, "\n"))
		}
		time.Sleep(time.Minute)
	}
}
