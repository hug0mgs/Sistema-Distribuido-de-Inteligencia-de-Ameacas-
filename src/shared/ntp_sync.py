"""
ntp_sync.py — Sincronização de Tempo via Protocolo NTP

PROBLEMA que este módulo resolve:
    Em um sistema distribuído, cada máquina tem seu próprio relógio
    local. Esses relógios podem ter DESVIOS (clock drift) de segundos
    ou até minutos entre si. Se o Agente A bane um IP às 14:00:00 por
    1 hora (unban às 15:00:00), mas o relógio do Agente B está 5 minutos
    atrasado, o Agente B faria o unban 5 minutos depois do esperado.

SOLUÇÃO — NTP (Network Time Protocol):
    NTP sincroniza o relógio de uma máquina com servidores de tempo
    de referência (atômicos/GPS). Em vez de usar time.time() (relógio
    local, possivelmente errado), consultamos um servidor NTP para
    obter o tempo UTC global.

    O NTP funciona assim:
      1. Cliente envia pacote UDP para o servidor NTP (porta 123)
      2. Servidor responde com o timestamp UTC preciso
      3. O protocolo calcula o round-trip delay para compensar
         a latência da rede

BIBLIOTECA ntplib:
    Biblioteca Python que implementa o cliente NTP (RFC 5905).
    Envia um pacote para o servidor NTP e retorna o timestamp UTC
    corrigido com a latência de rede.

    Instalação: pip install ntplib

ESTRATÉGIA DE FALLBACK (degradação graciosa):
    Se o servidor NTP estiver inacessível (rede fora, firewall, etc.),
    usamos time.time() como fallback — melhor ter um tempo aproximado
    do que nenhum tempo.
"""

# ntplib: cliente NTP — consulta servidores de tempo
import ntplib

# time: fallback para relógio local quando NTP falha
import time

# logging: registro de eventos
import logging

# datetime: conversão de timestamps para formato legível
from datetime import datetime, timezone

# Logger específico deste módulo
logger = logging.getLogger(__name__)


def get_ntp_time(ntp_server: str = "pool.ntp.org") -> float:
    """
    Consulta um servidor NTP e retorna o timestamp UTC atual.

    O timestamp retornado é um float Unix (segundos desde
    01/01/1970 00:00:00 UTC), igual ao formato de time.time(),
    mas sincronizado globalmente via NTP.

    Fluxo:
      1. Cria um cliente NTP (ntplib.NTPClient)
      2. Envia request UDP para o servidor NTP
      3. Recebe a resposta com o timestamp corrigido
      4. Retorna o campo tx_time (transmit timestamp)

    Se o NTP falhar, usa time.time() como fallback.

    Args:
        ntp_server: endereço do servidor NTP (padrão: pool.ntp.org).
                    pool.ntp.org é um pool global que roteia para
                    o servidor NTP mais próximo geograficamente.

    Returns:
        Timestamp Unix (float) em UTC.
    """
    try:
        # Criar instância do cliente NTP
        client = ntplib.NTPClient()

        # Enviar request para o servidor NTP
        # version=3: usar NTPv3 (compatível com a maioria dos servidores)
        # timeout=2: esperar no máximo 2 segundos pela resposta
        response = client.request(
            ntp_server,  # servidor NTP a consultar
            version=3,   # versão do protocolo NTP
            timeout=2,   # timeout em segundos
        )

        # Extrair o timestamp de transmissão (tx_time)
        # tx_time é o momento em que o servidor NTP enviou a resposta,
        # corrigido pelo round-trip delay
        ntp_timestamp = response.tx_time

        # Converter para formato legível para o log
        # fromtimestamp() converte Unix timestamp → datetime
        ntp_datetime = datetime.fromtimestamp(
            ntp_timestamp,    # timestamp a converter
            tz=timezone.utc,  # fuso horário UTC
        )

        # Log do tempo NTP obtido com sucesso
        logger.info(
            "Tempo NTP obtido: %s (offset: %.4fs)",  # mensagem
            ntp_datetime.strftime("%Y-%m-%d %H:%M:%S UTC"),  # data formatada
            response.offset,  # diferença entre relógio local e NTP
        )

        # Retornar o timestamp UTC como float
        return ntp_timestamp

    except ntplib.NTPException as e:
        # Erro do protocolo NTP (pacote corrompido, versão incompatível)
        logger.warning(
            "Erro NTP ao consultar '%s': %s. "  # mensagem
            "Usando relógio local como fallback.",
            ntp_server,  # servidor consultado
            e,           # detalhes do erro
        )
        # Fallback: usar relógio local
        return time.time()

    except OSError as e:
        # Erro de rede (servidor inacessível, DNS falhou, timeout)
        logger.warning(
            "Servidor NTP '%s' inacessível: %s. "  # mensagem
            "Usando relógio local como fallback.",
            ntp_server,  # servidor consultado
            e,           # detalhes do erro
        )
        # Fallback: usar relógio local
        return time.time()


def calculate_unban_time(
    ban_timestamp: float,   # momento do ban (Unix timestamp UTC)
    ban_duration: float,    # duração do ban em segundos
) -> float:
    """
    Calcula o momento exato de desbloqueio baseado no tempo NTP.

    A conta é simples: unban_time = ban_timestamp + ban_duration

    Mas a IMPORTÂNCIA está em que ban_timestamp veio do NTP (tempo
    global sincronizado), e NÃO do relógio local. Isso garante que
    TODOS os Agentes da rede calculam o MESMO momento de unban,
    independente do desvio dos seus relógios locais.

    Exemplo:
        ban_timestamp = 1720281600.0  (14:00:00 UTC via NTP)
        ban_duration  = 3600.0        (1 hora)
        unban_time    = 1720285200.0  (15:00:00 UTC)

    Args:
        ban_timestamp: timestamp Unix do momento do ban (via NTP).
        ban_duration: duração do ban em segundos.

    Returns:
        Timestamp Unix do momento de desbloqueio.
    """
    # Calcular o momento exato de desbloqueio
    unban_time = ban_timestamp + ban_duration

    # Converter ambos para formato legível para o log
    ban_dt = datetime.fromtimestamp(ban_timestamp, tz=timezone.utc)
    unban_dt = datetime.fromtimestamp(unban_time, tz=timezone.utc)

    # Log com os horários de ban e unban
    logger.info(
        "Ban: %s UTC → Unban: %s UTC (duração: %ds)",  # mensagem
        ban_dt.strftime("%H:%M:%S"),   # horário do ban
        unban_dt.strftime("%H:%M:%S"),  # horário do unban
        int(ban_duration),              # duração em segundos
    )

    # Retornar o timestamp de desbloqueio
    return unban_time


def is_ban_expired(
    unban_time: float,                          # momento do unban calculado
    ntp_server: str = "pool.ntp.org",           # servidor NTP para consulta
) -> bool:
    """
    Verifica se um ban já expirou comparando o tempo NTP atual
    com o momento de unban calculado.

    IMPORTANTE: usa tempo NTP (não local) para a comparação,
    garantindo consistência entre todos os Agentes da rede.

    Args:
        unban_time: timestamp Unix do momento de desbloqueio.
        ntp_server: servidor NTP para obter o tempo atual.

    Returns:
        True se o ban expirou (tempo atual >= unban_time).
        False se o ban ainda está ativo.
    """
    # Obter o tempo atual via NTP
    current_time = get_ntp_time(ntp_server)

    # Comparar: se o tempo atual ultrapassou o unban_time, expirou
    expired = current_time >= unban_time

    # Calcular quanto tempo resta (ou quanto tempo passou desde a expiração)
    remaining = unban_time - current_time

    if expired:
        # Ban expirou — log informativo
        logger.info(
            "Ban EXPIRADO (expirou há %.1fs)",  # mensagem
            abs(remaining),                      # tempo desde expiração
        )
    else:
        # Ban ainda ativo — log com tempo restante
        logger.debug(
            "Ban ATIVO (expira em %.1fs)",  # mensagem
            remaining,                       # tempo restante
        )

    # Retornar True se expirou, False se ainda ativo
    return expired
