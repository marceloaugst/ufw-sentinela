package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func servidores(t *testing.T) (geo, abuso *httptest.Server, nGeo, nAbuso *[]string) {
	nGeo, nAbuso = new([]string), new([]string)
	geo = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ips []string
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &ips)
		*nGeo = append(*nGeo, ips...)
		var res []map[string]string
		for _, ip := range ips {
			if ip == "192.0.2.99" {
				res = append(res, map[string]string{"status": "fail", "query": ip})
				continue
			}
			res = append(res, map[string]string{"status": "success", "country": "Brasil", "countryCode": "BR", "as": "AS1 Teste", "query": ip})
		}
		json.NewEncoder(w).Encode(res)
	}))
	abuso = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Key") != "CHAVE" {
			http.Error(w, "no", 401)
			return
		}
		*nAbuso = append(*nAbuso, r.URL.Query().Get("ipAddress"))
		w.Write([]byte(`{"data":{"abuseConfidenceScore":87}}`))
	}))
	t.Cleanup(geo.Close)
	t.Cleanup(abuso.Close)
	return
}

func TestGeoResolverECache(t *testing.T) {
	sg, sa, nGeo, nAbuso := servidores(t)
	arq := filepath.Join(t.TempDir(), "geo.json")
	g := novoGeo(arq, sg.URL, sa.URL, "CHAVE")
	ips := []string{"203.0.113.5", "10.0.0.1", "192.0.2.99", "203.0.113.5"}
	g.Resolver(ips, []string{"203.0.113.5"})

	if len(*nGeo) != 2 { // o privado e o repetido não são consultados
		t.Fatalf("consultas ao ip-api: %v", *nGeo)
	}
	if got := g.Texto("203.0.113.5"); got != "🇧🇷 Brasil · AS1 Teste · abuso 87%" {
		t.Fatalf("texto: %q", got)
	}
	if g.Texto("192.0.2.99") != "" || g.Texto("10.0.0.1") != "" {
		t.Fatal("IP sem dados deveria ter texto vazio")
	}
	if p, asn, ab := g.Colunas("203.0.113.5"); p != "Brasil" || asn != "AS1 Teste" || ab != 87 {
		t.Fatalf("colunas: %v %v %v", p, asn, ab)
	}

	// Segunda execução, lendo do disco: nada é consultado de novo.
	g2 := novoGeo(arq, sg.URL, sa.URL, "CHAVE")
	g2.Resolver(ips, []string{"203.0.113.5"})
	if len(*nGeo) != 2 || len(*nAbuso) != 1 {
		t.Fatalf("cache não funcionou: geo=%v abuso=%v", *nGeo, *nAbuso)
	}
}

func TestGeoSemChaveEFalhaDeRede(t *testing.T) {
	sg, sa, _, nAbuso := servidores(t)
	g := novoGeo(filepath.Join(t.TempDir(), "g.json"), sg.URL, sa.URL, "")
	g.Resolver([]string{"203.0.113.5"}, []string{"203.0.113.5"})
	if len(*nAbuso) != 0 || strings.Contains(g.Texto("203.0.113.5"), "abuso") {
		t.Fatal("sem chave não deve consultar o AbuseIPDB")
	}
	// Servidor fora do ar: não pode travar nem dar pânico.
	sg.Close()
	g2 := novoGeo(filepath.Join(t.TempDir(), "g.json"), sg.URL, sa.URL, "")
	g2.Resolver([]string{"198.51.100.1"}, nil)
	if g2.Texto("198.51.100.1") != "" {
		t.Fatal("sem rede não há dados")
	}
	var nulo *Geo
	nulo.Resolver([]string{"1.1.1.1"}, nil)
	if nulo.Texto("1.1.1.1") != "" {
		t.Fatal("Geo nil deve ser inofensivo")
	}
}

func TestEnriquecerAbasETextoPendentes(t *testing.T) {
	sg, sa, _, _ := servidores(t)
	g := novoGeo(filepath.Join(t.TempDir(), "g.json"), sg.URL, sa.URL, "CHAVE")
	g.Resolver([]string{"203.0.113.5"}, []string{"203.0.113.5"})
	abas := []Aba{
		{nome: "Usuários", cab: []string{"Usuário", "IP"}, larg: []float64{1, 1}, linhas: [][]any{{"root", "203.0.113.5"}}},
		{nome: "Log UFW", cab: []string{"x"}, larg: []float64{1}, linhas: [][]any{{"y"}}},
	}
	enriquecerAbas(abas, colunaIP, g)
	if len(abas[0].cab) != 5 || len(abas[0].larg) != 5 || len(abas[0].linhas[0]) != 5 || abas[0].linhas[0][2] != "Brasil" {
		t.Fatalf("aba Usuários: %+v", abas[0])
	}
	if len(abas[1].cab) != 1 || len(abas[1].linhas[0]) != 1 {
		t.Fatal("Log UFW não deveria ser alterada")
	}
	txt := textoPendentes([]string{"203.0.113.5", "198.51.100.1"}, g)
	if !strings.Contains(txt, "• 203.0.113.5 — 🇧🇷 Brasil") || !strings.Contains(txt, "• 198.51.100.1\n") {
		t.Fatalf("texto: %q", txt)
	}
}

func TestTecladoBan(t *testing.T) {
	t.Setenv("UFW_DURACAO_CURTA", "12h")
	t.Setenv("UFW_DURACAO_LONGA", "168h")
	var tec struct {
		Linhas [][]struct{ Text, Callback_data string } `json:"inline_keyboard"`
	}
	if err := json.Unmarshal([]byte(tecladoBan("ID1")), &tec); err != nil {
		t.Fatal(err)
	}
	var rot, dados []string
	for _, l := range tec.Linhas {
		for _, b := range l {
			rot, dados = append(rot, b.Text), append(dados, b.Callback_data)
		}
	}
	if strings.Join(rot, "|") != "✅ 12h|✅ 7d|♾ Permanente|❌ Não" ||
		strings.Join(dados, "|") != "banir_24h:ID1|banir_7d:ID1|banir_perm:ID1|banir_nao:ID1" {
		t.Fatalf("teclado: %v %v", rot, dados)
	}
}

func TestMesclarBansUfw(t *testing.T) {
	bans := map[string]*InfoBan{}
	mesclarBansUfw(bans, "Status: active\n--\n22/tcp ALLOW Anywhere\nAnywhere DENY 203.0.113.5\nAnywhere (v6) DENY IN 2001:db8::1 # x\n")
	if len(bans) != 2 || !bans["203.0.113.5"].banido() || !bans["2001:db8::1"].banido() {
		t.Fatalf("bans: %v", bans)
	}
	_, pend, _ := abaLimite("/nao/existe", Filtro{}, bans, [][]any{{"root", "203.0.113.5", 50}, {"root", "198.51.100.1", 50}}, 10)
	if len(pend) != 1 || pend[0] != "198.51.100.1" {
		t.Fatalf("pendentes: %v", pend)
	}
}
