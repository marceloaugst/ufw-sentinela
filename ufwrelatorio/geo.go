package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	arquivoGeo     = "log/geo_cache.json"
	validadeGeo    = 30 * 24 * time.Hour // país/ASN mudam raramente
	validadeAbuso  = 7 * 24 * time.Hour  // a nota de abuso muda mais
	maxNovosGeo    = 1000                // consultas novas por execução (ip-api: 15 lotes/min de 100)
	maxNovosAbuso  = 50                  // o plano grátis do AbuseIPDB dá 1000 consultas/dia
	tamanhoLoteGeo = 100
)

// InfoIP é o que se sabe sobre um IP. Abuso < 0 significa "não consultado".
type InfoIP struct {
	Codigo  string    `json:"codigo,omitempty"` // país em 2 letras (BR, US...)
	Pais    string    `json:"pais,omitempty"`
	ASN     string    `json:"asn,omitempty"`
	Abuso   int       `json:"abuso"`
	GeoEm   time.Time `json:"geo_em"`
	AbusoEm time.Time `json:"abuso_em"`
}

// Geo consulta e guarda em disco país/ASN (ip-api.com) e, se houver chave, a nota do AbuseIPDB.
// Um *Geo nil é válido e simplesmente não sabe nada (usado com -semgeo).
type Geo struct {
	cache      map[string]*InfoIP
	arquivo    string
	api        string // base do ip-api.com
	abuseAPI   string // base do AbuseIPDB
	abuseChave string
	cli        *http.Client
}

func novoGeo(arquivo, api, abuseAPI, abuseChave string) *Geo {
	g := &Geo{cache: map[string]*InfoIP{}, arquivo: arquivo, api: api, abuseAPI: abuseAPI,
		abuseChave: abuseChave, cli: &http.Client{Timeout: 20 * time.Second}}
	if dados, err := os.ReadFile(arquivo); err == nil {
		json.Unmarshal(dados, &g.cache) // cache corrompido = começa vazio
	}
	return g
}

// publico diz se vale consultar o IP (endereços locais/privados não existem na internet).
func publico(ip string) bool {
	a := net.ParseIP(ip)
	return a != nil && !(a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsUnspecified())
}

// Resolver preenche o cache para os IPs. "prioritarios" também recebem a nota de abuso.
// Falhas de rede não são erro fatal: o relatório sai sem aquele dado.
func (g *Geo) Resolver(ips, prioritarios []string) {
	if g == nil {
		return
	}
	agora := time.Now()
	var faltam []string
	visto := map[string]bool{}
	for _, ip := range ips {
		if visto[ip] || !publico(ip) {
			continue
		}
		visto[ip] = true
		if x := g.cache[ip]; x == nil || agora.Sub(x.GeoEm) > validadeGeo {
			faltam = append(faltam, ip)
		}
	}
	if len(faltam) > maxNovosGeo {
		faltam = faltam[:maxNovosGeo]
	}
	for len(faltam) > 0 {
		n := min(tamanhoLoteGeo, len(faltam))
		if err := g.lote(faltam[:n], agora); err != nil {
			fmt.Println("  aviso: geolocalização indisponível:", err)
			break
		}
		faltam = faltam[n:]
	}

	if g.abuseChave != "" {
		feitas := 0
		for _, ip := range prioritarios {
			if feitas >= maxNovosAbuso {
				break
			}
			x := g.cache[ip]
			if !publico(ip) || (x != nil && x.Abuso >= 0 && !x.AbusoEm.IsZero() && agora.Sub(x.AbusoEm) <= validadeAbuso) {
				continue
			}
			nota, err := g.abuso(ip)
			if err != nil {
				fmt.Println("  aviso: AbuseIPDB indisponível:", err)
				break
			}
			feitas++
			if x == nil {
				x = &InfoIP{}
				g.cache[ip] = x
			}
			x.Abuso, x.AbusoEm = nota, agora
		}
	}
	if err := g.salvar(); err != nil {
		fmt.Println("  aviso: não consegui gravar o cache de geolocalização:", err)
	}
}

// lote consulta até 100 IPs de uma vez no ip-api.com (endpoint /batch).
func (g *Geo) lote(ips []string, agora time.Time) error {
	corpo, _ := json.Marshal(ips)
	u := g.api + "/batch?lang=pt-BR&fields=status,country,countryCode,as,query"
	resp, err := g.cli.Post(u, "application/json", bytes.NewReader(corpo))
	if err != nil {
		return fmt.Errorf("falha de rede")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ip-api respondeu %d", resp.StatusCode)
	}
	var res []struct {
		Status, Country, CountryCode, As, Query string
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&res); err != nil {
		return err
	}
	for _, r := range res {
		if !publico(r.Query) {
			continue
		}
		x := g.cache[r.Query]
		if x == nil {
			x = &InfoIP{Abuso: -1}
			g.cache[r.Query] = x
		}
		x.GeoEm = agora // mesmo sem dados (status "fail"), para não repetir a consulta
		if r.Status == "success" {
			x.Codigo, x.Pais, x.ASN = r.CountryCode, r.Country, r.As
		}
	}
	return nil
}

// abuso devolve a "abuse confidence score" (0–100) do AbuseIPDB.
func (g *Geo) abuso(ip string) (int, error) {
	req, err := http.NewRequest(http.MethodGet, g.abuseAPI+"/api/v2/check?maxAgeInDays=90&ipAddress="+url.QueryEscape(ip), nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Key", g.abuseChave)
	req.Header.Set("Accept", "application/json")
	resp, err := g.cli.Do(req)
	if err != nil {
		return 0, fmt.Errorf("falha de rede")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("respondeu %d", resp.StatusCode)
	}
	var r struct {
		Data struct {
			Nota int `json:"abuseConfidenceScore"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r); err != nil {
		return 0, err
	}
	return r.Data.Nota, nil
}

// salvar grava o cache de forma atômica (arquivo temporário + rename).
func (g *Geo) salvar() error {
	dados, err := json.MarshalIndent(g.cache, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(g.arquivo), 0o755); err != nil {
		return err
	}
	tmp := g.arquivo + ".tmp"
	if err := os.WriteFile(tmp, dados, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, g.arquivo)
}

func (g *Geo) info(ip string) *InfoIP {
	if g == nil {
		return nil
	}
	return g.cache[ip]
}

// Colunas devolve País, ASN e nota de abuso para a planilha ("" quando não se sabe).
func (g *Geo) Colunas(ip string) (pais, asn string, abuso any) {
	x := g.info(ip)
	if x == nil {
		return "", "", ""
	}
	if x.Abuso >= 0 && !x.AbusoEm.IsZero() {
		abuso = x.Abuso
	} else {
		abuso = ""
	}
	return x.Pais, x.ASN, abuso
}

// Texto resume o IP numa linha para a mensagem do Telegram. Vazio se nada se sabe.
func (g *Geo) Texto(ip string) string {
	x := g.info(ip)
	if x == nil {
		return ""
	}
	var p []string
	if x.Pais != "" {
		p = append(p, bandeira(x.Codigo)+x.Pais)
	}
	if x.ASN != "" {
		p = append(p, x.ASN)
	}
	if x.Abuso >= 0 && !x.AbusoEm.IsZero() {
		p = append(p, fmt.Sprintf("abuso %d%%", x.Abuso))
	}
	return strings.Join(p, " · ")
}

// bandeira transforma "BR" no emoji da bandeira (seguido de espaço); "" se o código for inválido.
func bandeira(codigo string) string {
	if len(codigo) != 2 {
		return ""
	}
	var r []rune
	for _, c := range strings.ToUpper(codigo) {
		if c < 'A' || c > 'Z' {
			return ""
		}
		r = append(r, 0x1F1E6+(c-'A'))
	}
	return string(r) + " "
}

// enriquecerAbas acrescenta País, ASN e Abuso% ao fim das abas que têm uma coluna de IP.
func enriquecerAbas(abas []Aba, colIP map[string]int, g *Geo) {
	for i := range abas {
		col, ok := colIP[abas[i].nome]
		if !ok || g == nil {
			continue
		}
		abas[i].cab = append(abas[i].cab, "País", "ASN", "Abuso (%)")
		abas[i].larg = append(abas[i].larg, 18, 40, 11)
		for j, l := range abas[i].linhas {
			ip, _ := l[col].(string)
			pais, asn, abuso := g.Colunas(ip)
			abas[i].linhas[j] = append(l, pais, asn, abuso)
		}
	}
}

// textoPendentes monta a mensagem com cada IP proposto para ban e o seu contexto.
func textoPendentes(ips []string, g *Geo) string {
	const maxLinhas = 40 // mensagem do Telegram tem limite de 4096 caracteres
	var sb strings.Builder
	sb.WriteString("IPs propostos para banir:")
	for i, ip := range ips {
		if i == maxLinhas {
			fmt.Fprintf(&sb, "\n... e mais %d", len(ips)-maxLinhas)
			break
		}
		sb.WriteString("\n• " + ip)
		if t := g.Texto(ip); t != "" {
			sb.WriteString(" — " + t)
		}
	}
	sb.WriteString("\n\nQuer banir estes IPs?")
	return sb.String()
}
