# Evoluir o ufwbot / ufwrelatorio

Plano para fazer por partes. Cada etapa é independente e termina com algo que funciona.
Marque `[x]` ao concluir.

## Etapa 1 — Comandos no bot
- [x] `/status`: resumo do UFW (ativo, nº de regras, nº de IPs banidos)
- [x] `/banidos`: lista os IPs banidos pelo bot
- [x] `/desbanir <ip>`: remove o ban (só para o chat autorizado, valida o IP)
- [x] `/top`: os 10 IPs com mais tentativas hoje
- [x] `/relatorio`: gera e envia o xlsx na hora

**Pronto quando:** todos os comandos respondem só ao chat autorizado e têm teste em `main_test.go`.

## Etapa 2 — Geolocalização e reputação do IP
- [x] Consultar país e ASN (ex.: ip-api.com ou base MaxMind GeoLite2 local)
- [x] Opcional: nota de abuso no AbuseIPDB (precisa de chave de API)
- [x] Mostrar país/ASN/nota no xlsx e na mensagem do Telegram
- [x] Cache local para não repetir consultas do mesmo IP

**Pronto quando:** a mensagem com os botões Sim/Não já traz o contexto de cada IP.

## Etapa 3 — Banimento temporário
- [x] Guardar data de expiração de cada ban (arquivo JSON ou SQLite)
- [x] Rotina que remove bans vencidos (24h / 7 dias, configurável)
- [x] Botões de duração na confirmação: 24h / 7d / permanente

**Pronto quando:** a lista de bans deixa de crescer sem limite.

## Etapa 4 — Banimento automático por limiar
- [x] Definir regra: mais de N tentativas em X minutos → ban automático
- [x] Casos duvidosos (poucas tentativas, IP na lista `nuncaBanir`) continuam pedindo confirmação
- [x] Avisar no Telegram o que foi banido sozinho, com botão "Desfazer"

**Pronto quando:** ataques óbvios são bloqueados sem você precisar clicar.

## Etapa 5 — Alerta em tempo real
- [x] Ler o log do UFW continuamente (tail) em vez de só no relatório diário
- [x] Avisar em picos de tentativas, varredura de portas e SSH de IP novo
- [x] Limitar a frequência dos alertas para não virar spam

## Etapa 6 — Gráficos
- [x] Tentativas por hora e por país
- [x] Enviar como imagem no Telegram (`sendPhoto`)

## Etapa 7 — Desempenho (opcional)
- [ ] Trocar bans individuais do `ufw` por um conjunto (ipset/nftables) para suportar milhares de IPs
- [ ] Avaliar fail2ban para a parte de detecção

## Antes de começar qualquer etapa
- Extrair o código comum de Telegram dos dois programas para um pacote compartilhado
- Manter os testes passando (`go test ./...`) a cada etapa
- Nunca guardar o token do bot no repositório
