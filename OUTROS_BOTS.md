# Outros bots úteis (para decidir depois)

Marque o que quiser fazer. Esforço: baixo / médio / alto.

## Monitor do servidor — esforço baixo (feito no ufwbot, veja README)
- CPU, disco, RAM, serviços caídos (`systemctl`), certificado SSL perto de vencer
- Comandos sob demanda: `/df`, `/uptime`, `/servicos`
- Alerta automático quando passar de um limite (ex.: disco > 90%)

## Aviso de login SSH — esforço baixo
- Mensagem a cada login bem-sucedido (usuário, IP, país)
- Botão "Não fui eu" que derruba a sessão e bane o IP
- Encaixa bem com o ufwbot atual

## Backup — esforço baixo
- Backup agendado (cron/systemd timer) com resultado no Telegram
- `/backup` para rodar na hora
- Avisar se o backup falhar ou ficar velho

## Lembretes e tarefas — esforço médio
- `/lembrar amanhã 9h pagar conta`
- Integração com o Todoist (criar e concluir tarefas pelo bot)
- Resumo diário das tarefas do dia

## Controle remoto — esforço médio (cuidado com segurança)
- `/reiniciar <serviço>` e similares
- Somente comandos de uma whitelist, só o seu chat, com confirmação por botão
- Registrar tudo em log

## Feeds e preços — esforço baixo
- RSS, cotação do dólar/cripto, previsão do tempo
- Avisos de promoção ou de mudança em uma página
- Envio agendado ou só quando passar de um valor

## Bot de estudo — esforço médio
- Flashcards com repetição espaçada
- Quiz diário (Go ou outra matéria) com resposta por botão inline
- Estatística de acertos por assunto

## Bot com IA (Claude) — esforço médio
- Você manda pergunta ou áudio e ele responde pela API do Claude
- Resumo de links e PDFs enviados ao bot
- Cuidar do custo: limite diário de uso e só o seu chat autorizado

## Projetos de estudo em Go — esforço variado
- Encurtador de URL ou API REST com SQLite
- Scraper com agendamento
- Mini-framework de bot, reaproveitando o código de Telegram dos programas atuais

## Dicas gerais
- Todos podem partir do mesmo pacote de Telegram (enviar mensagem, botões, comandos, checagem do chat autorizado)
- Um token de bot por projeto, fora do repositório
- Comece pelos de esforço baixo: dão resultado rápido
