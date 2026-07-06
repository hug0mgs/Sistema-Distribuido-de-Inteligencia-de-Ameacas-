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
MAX_FAILED_ATTEMPTS = 5

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
BROKER_HOST = "127.0.0.1"

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
