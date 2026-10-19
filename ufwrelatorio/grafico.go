package main

import (
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
)

var (
	corFundo = color.RGBA{255, 255, 255, 255}
	corBarra = color.RGBA{0x30, 0x54, 0x96, 255} // a mesma cor do cabeçalho do xlsx
	corGrade = color.RGBA{225, 225, 225, 255}
	corTexto = color.RGBA{40, 40, 40, 255}
)

// semAcento deixa o texto em ASCII: a fonte embutida (basicfont) só desenha esses caracteres.
var semAcento = strings.NewReplacer(
	"á", "a", "à", "a", "â", "a", "ã", "a", "ä", "a", "Á", "A", "À", "A", "Â", "A", "Ã", "A",
	"é", "e", "ê", "e", "è", "e", "ë", "e", "É", "E", "Ê", "E",
	"í", "i", "î", "i", "ï", "i", "Í", "I",
	"ó", "o", "ô", "o", "õ", "o", "ö", "o", "Ó", "O", "Ô", "O", "Õ", "O",
	"ú", "u", "û", "u", "ü", "u", "Ú", "U", "ç", "c", "Ç", "C", "ñ", "n", "—", "-", "–", "-")

func texto(img *image.RGBA, x, y int, s string) {
	d := font.Drawer{Dst: img, Src: image.NewUniform(corTexto), Face: basicfont.Face7x13,
		Dot: fixed.P(x, y)}
	d.DrawString(semAcento.Replace(s))
}

func larguraTexto(s string) int { return len([]rune(semAcento.Replace(s))) * 7 }

func retangulo(img *image.RGBA, x0, y0, x1, y1 int, c color.Color) {
	draw.Draw(img, image.Rect(x0, y0, x1, y1), image.NewUniform(c), image.Point{}, draw.Src)
}

// passoEixo escolhe um intervalo "redondo" (1, 2, 5, 10, 20, 50...) para ~4 linhas de grade.
func passoEixo(max int) int {
	for m := 1; ; m *= 10 {
		for _, base := range []int{1, 2, 5} {
			if p := base * m; max/p <= 5 {
				return p
			}
		}
	}
}

// barrasVerticais desenha um gráfico de colunas (usado para "bloqueios por hora").
func barrasVerticais(titulo string, rotulos []string, valores []int) *image.RGBA {
	const w, h, ml, mr, mt, mb = 900, 420, 60, 20, 50, 40
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	retangulo(img, 0, 0, w, h, corFundo)
	texto(img, ml, 25, titulo)
	maxV := 1
	for _, v := range valores {
		maxV = max(maxV, v)
	}
	passo := passoEixo(maxV)
	topo := (maxV + passo - 1) / passo * passo
	area := h - mt - mb
	for v := 0; v <= topo; v += passo {
		y := h - mb - v*area/topo
		retangulo(img, ml, y, w-mr, y+1, corGrade)
		s := strconv.Itoa(v)
		texto(img, ml-8-larguraTexto(s), y+4, s)
	}
	larg := (w - ml - mr) / len(valores)
	for i, v := range valores {
		x := ml + i*larg
		alt := v * area / topo
		retangulo(img, x+3, h-mb-alt, x+larg-3, h-mb, corBarra)
		if v > 0 {
			s := strconv.Itoa(v)
			texto(img, x+(larg-larguraTexto(s))/2, h-mb-alt-4, s)
		}
		texto(img, x+(larg-larguraTexto(rotulos[i]))/2, h-mb+16, rotulos[i])
	}
	return img
}

// barrasHorizontais desenha um ranking (usado para "bloqueios por país").
func barrasHorizontais(titulo string, rotulos []string, valores []int) *image.RGBA {
	const w, ml, mr, mt, linha = 900, 190, 80, 50, 28
	h := mt + len(valores)*linha + 20
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	retangulo(img, 0, 0, w, h, corFundo)
	texto(img, 20, 25, titulo)
	maxV := 1
	for _, v := range valores {
		maxV = max(maxV, v)
	}
	for i, v := range valores {
		y := mt + i*linha
		r := rotulos[i]
		for larguraTexto(r) > ml-20 {
			r = string([]rune(r)[:len([]rune(r))-1])
		}
		texto(img, ml-10-larguraTexto(r), y+16, r)
		retangulo(img, ml, y+3, ml+v*(w-ml-mr)/maxV, y+linha-5, corBarra)
		texto(img, ml+v*(w-ml-mr)/maxV+6, y+16, strconv.Itoa(v))
	}
	return img
}

func salvarPNG(img image.Image, caminho string) error {
	f, err := os.Create(caminho)
	if err != nil {
		return err
	}
	if err := png.Encode(f, img); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// bloqueiosPorHora conta os BLOCK do UFW por hora do dia (0–23) a partir das linhas da aba "Log UFW".
func bloqueiosPorHora(linhasUfw [][]any) [24]int {
	var h [24]int
	for _, l := range linhasUfw {
		t, ok := l[0].(time.Time)
		if ok && l[1] == "BLOCK" {
			h[t.Hour()]++
		}
	}
	return h
}

// bloqueiosPorPais conta os BLOCK por país de origem e devolve os 10 maiores. IPs sem dado
// de geolocalização entram em "Desconhecido".
func bloqueiosPorPais(linhasUfw [][]any, g *Geo) (rotulos []string, valores []int) {
	cont := map[string]int{}
	for _, l := range linhasUfw {
		if l[1] != "BLOCK" {
			continue
		}
		ip, _ := l[3].(string)
		pais, _, _ := g.Colunas(ip)
		if pais == "" {
			pais = "Desconhecido"
		}
		cont[pais]++
	}
	for _, kv := range topoMapa(cont, 10) {
		rotulos, valores = append(rotulos, kv.k), append(valores, kv.v)
	}
	return
}

// gerarGraficos grava os PNGs em "pasta" e devolve os caminhos (vazio se não há dados).
func gerarGraficos(pasta string, carimbo string, periodo string, linhasUfw [][]any, g *Geo) ([]string, error) {
	var saida []string
	porHora := bloqueiosPorHora(linhasUfw)
	total := 0
	rot := make([]string, 24)
	val := make([]int, 24)
	for i, v := range porHora {
		rot[i], val[i] = fmt.Sprintf("%02d", i), v
		total += v
	}
	if total == 0 {
		return nil, nil
	}
	c := pasta + "/grafico_horas_" + carimbo + ".png"
	if err := salvarPNG(barrasVerticais("Bloqueios por hora do dia - "+periodo, rot, val), c); err != nil {
		return saida, err
	}
	saida = append(saida, c)
	if g != nil {
		rotulos, valores := bloqueiosPorPais(linhasUfw, g)
		c = pasta + "/grafico_paises_" + carimbo + ".png"
		if err := salvarPNG(barrasHorizontais("Bloqueios por pais (top 10) - "+periodo, rotulos, valores), c); err != nil {
			return saida, err
		}
		saida = append(saida, c)
	}
	return saida, nil
}
