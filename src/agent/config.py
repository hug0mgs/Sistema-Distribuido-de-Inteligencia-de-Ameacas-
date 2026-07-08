"""
Configurações centralizadas do Agente.
Separar configuração de lógica facilita a manutenção
e permite diferentes valores por ambiente (dev/prod).
"""

# ============================================================
# Monitoramento de Logs
# ============================================================
# Caminho do arquivo de log do SSH no Debian/Ubuntu
AUTH_LOG_PATH = "/var/log/auth.log"

# Intervalo (em segundos) entre cada tentativa de leitura de novas linhas.
# Valor baixo = reação rápida, mas mais uso de CPU.
# Valor alto = menos CPU, mas demora para detectar ataques.
LOG_POLL_INTERVAL = 1.0

# Número máximo de tentativas falhas de SSH antes de banir o IP
MAX_FAILED_ATTEMPTS = 3

# Janela de tempo (em segundos) para contar as tentativas.
# Se um IP faz 5 tentativas em 600s (10 min), é banido.
FAILED_ATTEMPT_WINDOW = 600

# ============================================================
# Bloqueio (Ban/Unban)
# ============================================================
# Duração padrão do banimento em segundos (1 hora)
DEFAULT_BAN_DURATION = 3600

# ============================================================
# Rede — Conexão com o Broker
# ============================================================
# Endereço IP do Broker (Servidor de Coordenação)
BROKER_HOST = "192.168.15.7"

# Endereço IP original do Broker (para Recovery Probe / Failback).
# Mantido separado do BROKER_HOST porque BROKER_HOST pode mudar
# dinamicamente durante a eleição (apontar para o Broker Temporário).
# Este valor NUNCA muda — é sempre o IP da máquina do Broker original.
ORIGINAL_BROKER_HOST = "192.168.15.7"

# Porta TCP do Broker para envio/recebimento de alertas
BROKER_TCP_PORT = 5600

# Porta UDP do Broker para recebimento de Heartbeats
BROKER_UDP_PORT = 5601

# Intervalo de envio do Heartbeat UDP (em segundos)
HEARTBEAT_INTERVAL = 10

# ============================================================
# NTP
# ============================================================
# Servidor NTP para sincronização de tempo
NTP_SERVER = "pool.ntp.org"

# ============================================================
# Eleição de Líder (Bully Algorithm)
# ============================================================
# Porta UDP para comunicação P2P entre Agentes durante a eleição.
# Cada Agente escuta nesta porta para mensagens ELECTION, OK,
# COORDINATOR e DEMOTION.
ELECTION_UDP_PORT = 5602

# Tempo de tolerância (em segundos) antes de considerar o Broker morto.
# Generoso para evitar eleições desnecessárias por instabilidades
# momentâneas de rede (micro-quedas, congestionamento, etc.).
# São ~6 ciclos de reconexão de 5s.
BROKER_FAILURE_TOLERANCE = 30

# Timeout (em segundos) para esperar respostas "OK" durante a eleição.
# Se nenhum Agente com ID maior responder em ELECTION_TIMEOUT segundos,
# este Agente se declara líder (novo Broker Temporário).
ELECTION_TIMEOUT = 5

# Intervalo (em segundos) entre tentativas de reconectar ao Broker
# original. O Broker Temporário tenta reconectar periodicamente para
# verificar se o original voltou (Recovery Probe).
RECOVERY_PROBE_INTERVAL = 30

# Tempo máximo total (em segundos) que o Broker Temporário fica
# tentando reconectar ao Broker original. Após esse tempo, assume
# o papel permanentemente e para de tentar recovery.
# 600s = 10 minutos → ~20 tentativas de recovery (600 / 30)
RECOVERY_PROBE_MAX_DURATION = 600

# IMPORTANTE: A lista de PEERS não precisa mais ser configurada
# manualmente. O sistema utiliza Service Discovery: o Broker atua
# como Registro Central e faz o broadcast da topologia da rede para
# todos os Agentes conectados automaticamente.
