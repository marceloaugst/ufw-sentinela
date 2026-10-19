# ufw-guard

Vigia o firewall UFW de um servidor Linux e conversa com você pelo Telegram.
Dois programas em Go:

| Programa | O que faz |
|---|---|
| `ufwrelatorio` | Lê os logs (UFW, fail2ban, SSH), gera um relatório `.xlsx` com abas, gráficos e geolocalização, e envia ao Telegram. Propõe os IPs que passaram do limite para banir. |
| `ufwbot` | Fica rodando como serviço: recebe comandos e cliques nos botões, bane/desbane no `ufw`, bane sozinho ataques óbvios e manda alertas em tempo real. |

## Recursos

- **Comandos no bot:** `/status`, `/banidos`, `/desbanir <ip>`, `/top`, `/relatorio`. Dizer "oi" (ou `/start`) mostra data, hora e botões de atalho; `/ajuda` lista os comandos.
- **Relatório diário** em `.xlsx`: log do UFW, IPs banidos, bloqueados sem ban, perto do limite, usuários tentados.
- **Geolocalização** (país/ASN via ip-api.com) e nota de abuso opcional (AbuseIPDB), com cache local.
- **Banimento com duração:** botões 24h / 7d / permanente; o bot remove os bans vencidos sozinho.
- **Ban automático:** mais de N tentativas em X minutos bane na hora, avisa e tem botão "Desfazer".
- **Alertas em tempo real:** pico de tentativas, varredura de portas, login SSH de IP novo, com limite de frequência.
- **Gráficos** (bloqueios por hora e por país) enviados como imagem.

## Segurança

- Só o chat de `TELEGRAM_CHAT_ID` é atendido; qualquer outro é ignorado em silêncio.
- IPs inválidos, privados/locais e os de `UFW_NUNCA_BANIR` nunca são banidos. **Coloque o seu IP lá.**
- O IP é validado e passado ao `ufw` como argumento (sem shell), então não há injeção de comando.
- Cada lista de pendentes só vale uma vez (clique duplo não bane duas vezes).
- O token nunca é gravado no repositório nem aparece nos erros.
- Os dados da consulta de país vão por HTTP ao ip-api.com (plano grátis). Use `-semgeo` para desligar.

## Requisitos

- Linux com `ufw` ativo e logs em `/var/log/ufw.log` (e `auth.log`; `fail2ban.log` é opcional).
- Go 1.26+ para compilar.
- Rodar como **root** (precisa executar `ufw` e ler os logs).

## Instalação

```bash
# 1. Compilar
cd ufwbot && go build -o ufwbot . && cd ..
cd ufwrelatorio && go build -o ufwrelatorio . && cd ..

# 2. Instalar
sudo mkdir -p /opt/ufw/bot /opt/ufw/relatorio
sudo cp ufwbot/ufwbot /opt/ufw/bot/
sudo cp ufwrelatorio/ufwrelatorio /opt/ufw/relatorio/

# 3. Configurar (edite o arquivo e preencha token e chat id)
sudo cp .env.example /etc/ufwrelatorio.env
sudo chmod 600 /etc/ufwrelatorio.env
sudo nano /etc/ufwrelatorio.env

# 4. Serviço do bot
sudo cp ufwbot/ufwbot.service /etc/systemd/system/
sudo nano /etc/systemd/system/ufwbot.service   # ajuste o ExecStart
sudo systemctl daemon-reload
sudo systemctl enable --now ufwbot
```

No `ufwbot.service`, use `ExecStart=/opt/ufw/bot/ufwbot` e acrescente
`WorkingDirectory=/opt/ufw/relatorio` para o bot achar a pasta `log/` e o relatório.

### Relatório automático

O relatório é executado dentro da sua pasta (ele grava em `log/`). Exemplo no cron do root,
todo dia às 23:55:

```
55 23 * * * cd /opt/ufw/relatorio && env $(cat /etc/ufwrelatorio.env | grep -v '^#' | xargs) ./ufwrelatorio -hoje
```

Opções do `ufwrelatorio`: `-hoje`, `-de DD/MM/AAAA`, `-ate DD/MM/AAAA`, `-limite N`
(tentativas por IP para propor ban, padrão 10), `-semgeo`.

## Como funciona

```
 logs (ufw, auth, fail2ban)
        │
        ├── ufwrelatorio ──► xlsx + gráficos + lista de IPs pendentes ──► Telegram
        │                                              │ (botões 24h / 7d / permanente / Não)
        │                                              ▼
        └── ufwbot (lê os logs a cada 15 s) ◄── cliques e comandos ── Telegram
                 │
                 ├── ban automático (limiar) ──► ufw + bans.json ──► aviso com "Desfazer"
                 ├── alertas (pico, varredura, SSH novo)
                 └── a cada minuto remove bans vencidos
```

Arquivos de estado (em `log/`, nunca vão para o git): `pendentes.json` (lista aguardando
resposta), `bans.json` (quando cada ban expira), `ssh_conhecidos.json` (IPs que já logaram),
`geo_cache.json` (país/ASN/abuso).

## Configuração

Tudo por variáveis de ambiente; veja os valores padrão e comentários em
[`.env.example`](.env.example).

## Testes

```bash
cd ufwbot && go test ./...
cd ../ufwrelatorio && go test ./...
```

## Roteiro

O que foi feito e o que falta está em [EVOLUIR.md](EVOLUIR.md). Ideias de outros bots em
[OUTROS_BOTS.md](OUTROS_BOTS.md).
