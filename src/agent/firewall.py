"""
firewall.py — Gerenciamento de Firewall (iptables) e Auto-Unban

Este módulo é responsável por:
  1. Bloquear IPs via iptables (ban)
  2. Desbloquear IPs via iptables (unban)
  3. Agendar desbloqueios automáticos usando timestamps NTP
  4. Manter uma thread que verifica periodicamente se há bans expirados

IPTABLES — O Firewall do Linux:
    iptables é a ferramenta padrão de firewall no Linux. Funciona com
    "regras" que dizem ao kernel como tratar pacotes de rede:
      - INPUT: pacotes ENTRANDO no servidor (é aqui que bloqueamos)
      - OUTPUT: pacotes SAINDO do servidor
      - FORWARD: pacotes sendo roteados por este servidor

    Comando para bloquear um IP:
      iptables -A INPUT -s <IP> -j DROP
        -A INPUT = adicionar regra na chain INPUT (pacotes de entrada)
        -s <IP>  = source (IP de origem) a ser bloqueado
        -j DROP  = jump to DROP (descartar o pacote silenciosamente)

    Comando para desbloquear:
      iptables -D INPUT -s <IP> -j DROP
        -D INPUT = deletar a regra da chain INPUT

THREAD BanManager:
    Mantém um dicionário de IPs banidos com seus timestamps de unban.
    A cada UNBAN_CHECK_INTERVAL segundos, verifica se algum ban expirou
    usando tempo NTP e executa o desbloqueio automaticamente.

REQUER SUDO:
    iptables só pode ser executado como root (sudo). O Agente inteiro
    deve ser executado com sudo para que este módulo funcione.
"""

# subprocess: executa comandos do sistema operacional (iptables)
import subprocess

# threading: thread para verificação periódica de bans expirados
import threading

# time: sleep para intervalos de verificação
import time

# logging: registro de eventos
import logging

# Nosso módulo de sincronização NTP
from shared.ntp_sync import get_ntp_time, calculate_unban_time, is_ban_expired

# Configurações do Agente
from agent import config

# Logger específico deste módulo
logger = logging.getLogger(__name__)

# ============================================================
# Constantes
# ============================================================
# Intervalo (em segundos) entre verificações de bans expirados.
# A cada 30 segundos, a thread BanManager checa se há IPs para desbloquear.
UNBAN_CHECK_INTERVAL = 30


def block_ip(ip: str) -> bool:
    """
    Bloqueia um IP no firewall local usando iptables.

    Executa: iptables -A INPUT -s <IP> -j DROP

    Este comando adiciona uma regra na chain INPUT que DESCARTA
    silenciosamente todos os pacotes vindos do IP especificado.
    O atacante não recebe nenhuma resposta (diferente de REJECT,
    que envia uma mensagem de recusa).

    DROP vs REJECT:
      - DROP: descarta silenciosamente (o atacante não sabe se o
        servidor existe). Mais seguro para ataques.
      - REJECT: envia resposta de recusa (o atacante sabe que o
        servidor existe). Mais educado para erros legítimos.

    Args:
        ip: endereço IPv4 a ser bloqueado (ex: "192.168.1.100").

    Returns:
        True se o comando executou com sucesso.
        False se houve erro (sem sudo, iptables não instalado, etc.).
    """
    try:
        # Executar o comando iptables para adicionar regra de bloqueio
        result = subprocess.run(
            [
                "iptables",     # comando do firewall
                "-A", "INPUT",  # adicionar (-A) na chain INPUT
                "-s", ip,       # source: IP a bloquear
                "-j", "DROP",   # ação: descartar pacote silenciosamente
            ],
            capture_output=True,  # capturar stdout e stderr
            text=True,            # decodificar saída como texto (não bytes)
            check=False,          # não levantar exceção se falhar
        )

        # Verificar se o comando foi bem-sucedido
        if result.returncode == 0:
            # Sucesso — regra adicionada ao iptables
            logger.info(
                "FIREWALL: IP %s BLOQUEADO com sucesso (iptables DROP)",
                ip,  # IP bloqueado
            )
            # Retornar True indicando sucesso
            return True
        else:
            # Falha — logar a mensagem de erro do iptables
            logger.error(
                "FIREWALL: Falha ao bloquear IP %s: %s",  # mensagem
                ip,                                        # IP
                result.stderr.strip(),                     # erro do iptables
            )
            # Retornar False indicando falha
            return False

    except FileNotFoundError:
        # iptables não está instalado no sistema
        logger.error(
            "FIREWALL: iptables não encontrado. "
            "Instale com: sudo apt install iptables"
        )
        # Retornar False indicando falha
        return False

    except PermissionError:
        # Falta de permissão (programa não executado com sudo)
        logger.error(
            "FIREWALL: Sem permissão para executar iptables. "
            "Execute o Agente com: sudo python -m agent.main"
        )
        # Retornar False indicando falha
        return False


def unblock_ip(ip: str) -> bool:
    """
    Desbloqueia um IP no firewall local usando iptables.

    Executa: iptables -D INPUT -s <IP> -j DROP

    Este comando REMOVE a regra de bloqueio que foi adicionada
    por block_ip(). Após a remoção, o IP volta a poder se comunicar
    normalmente com o servidor.

    Args:
        ip: endereço IPv4 a ser desbloqueado (ex: "192.168.1.100").

    Returns:
        True se o comando executou com sucesso.
        False se houve erro.
    """
    try:
        # Executar o comando iptables para remover regra de bloqueio
        result = subprocess.run(
            [
                "iptables",     # comando do firewall
                "-D", "INPUT",  # deletar (-D) da chain INPUT
                "-s", ip,       # source: IP a desbloquear
                "-j", "DROP",   # ação que estava configurada
            ],
            capture_output=True,  # capturar stdout e stderr
            text=True,            # decodificar saída como texto
            check=False,          # não levantar exceção se falhar
        )

        # Verificar se o comando foi bem-sucedido
        if result.returncode == 0:
            # Sucesso — regra removida do iptables
            logger.info(
                "FIREWALL: IP %s DESBLOQUEADO com sucesso",  # mensagem
                ip,                                           # IP desbloqueado
            )
            # Retornar True indicando sucesso
            return True
        else:
            # Falha — provavelmente a regra não existia (já foi removida)
            logger.warning(
                "FIREWALL: Falha ao desbloquear IP %s: %s",  # mensagem
                ip,                                           # IP
                result.stderr.strip(),                        # erro do iptables
            )
            # Retornar False indicando falha
            return False

    except FileNotFoundError:
        # iptables não está instalado
        logger.error(
            "FIREWALL: iptables não encontrado. "
            "Instale com: sudo apt install iptables"
        )
        return False

    except PermissionError:
        # Falta de permissão
        logger.error(
            "FIREWALL: Sem permissão para executar iptables. "
            "Execute o Agente com: sudo python -m agent.main"
        )
        return False


class BanManager(threading.Thread):
    """
    Thread que gerencia o ciclo de vida dos bans (bloqueios).

    Responsabilidades:
      1. Registrar novos bans com timestamp NTP e duração
      2. Executar bloqueio via iptables (block_ip)
      3. Verificar periodicamente se algum ban expirou
      4. Executar desbloqueio automático (unblock_ip)

    O tempo de expiração é calculado usando timestamps NTP,
    garantindo que TODOS os Agentes da rede desbloqueiam o IP
    no MESMO momento, independente do clock drift local.

    Atributos:
        _active_bans: dicionário {ip: unban_timestamp}
            Protegido por lock para acesso thread-safe.
        _bans_lock: mutex para acesso ao dicionário
        _stop_event: sinaliza encerramento da thread
    """

    def __init__(self):
        # daemon=True: thread morre automaticamente com o programa
        # name: identificador legível para logs e debugging
        super().__init__(daemon=True, name="BanManagerThread")

        # Dicionário de bans ativos: {ip: unban_timestamp}
        # O unban_timestamp é calculado via NTP + duração
        self._active_bans: dict[str, float] = {}

        # Lock para acesso thread-safe ao dicionário de bans
        # Necessário porque múltiplas fontes podem registrar bans:
        # LogMonitor (local) e NetworkListener (rede)
        self._bans_lock = threading.Lock()

        # Evento de parada para encerramento gracioso
        self._stop_event = threading.Event()

    def stop(self):
        """Sinaliza para a thread encerrar na próxima iteração."""
        logger.info("Sinalizando parada da thread BanManager...")
        # Marcar evento de parada
        self._stop_event.set()

    def register_ban(
        self,
        ip: str,             # IP a ser banido
        ban_timestamp: float,  # timestamp do ban (via NTP)
        ban_duration: float,  # duração do ban em segundos
    ):
        """
        Registra um novo ban: bloqueia o IP via iptables e agenda
        o desbloqueio automático.

        Passos:
          1. Calcular o momento de unban (ban_timestamp + duration)
          2. Executar block_ip() para adicionar regra no iptables
          3. Armazenar no dicionário de bans ativos (com lock)

        Args:
            ip: endereço IPv4 a ser bloqueado.
            ban_timestamp: timestamp Unix UTC do momento do ban (via NTP).
            ban_duration: duração do bloqueio em segundos.
        """
        # Calcular o momento exato de desbloqueio usando NTP
        unban_time = calculate_unban_time(ban_timestamp, ban_duration)

        # Executar o bloqueio no firewall
        success = block_ip(ip)

        if success:
            # Bloqueio bem-sucedido — registrar no dicionário
            with self._bans_lock:
                # Armazenar o IP e o momento de desbloqueio
                self._active_bans[ip] = unban_time

            # Log do ban registrado
            logger.info(
                "Ban registrado: IP=%s, unban em %.0fs",  # mensagem
                ip,                                        # IP banido
                ban_duration,                              # duração
            )
        else:
            # Falha no iptables — logar aviso
            # O ban é registrado mesmo assim para manter consistência
            # com a rede (outros Agentes estão bloqueando)
            logger.warning(
                "Falha no iptables para IP %s, mas registrando "
                "na lista de bans para consistência.",
                ip,  # IP
            )
            # Registrar mesmo assim (para eventual retry ou unban futuro)
            with self._bans_lock:
                self._active_bans[ip] = unban_time

    def run(self):
        """
        Loop principal da thread BanManager.

        A cada UNBAN_CHECK_INTERVAL segundos, verifica se algum ban
        ativo expirou. Se sim, executa o desbloqueio via iptables
        e remove o IP do dicionário.

        Usa _stop_event.wait() em vez de time.sleep() para permitir
        encerramento rápido quando stop() é chamado.
        """
        logger.info(
            "Thread BanManager iniciada. Verificando bans a cada %ds.",
            UNBAN_CHECK_INTERVAL,  # intervalo de verificação
        )

        # Loop até receber sinal de parada
        while not self._stop_event.is_set():
            # Verificar bans expirados
            self._check_expired_bans()

            # Esperar o intervalo (interrompível pelo stop_event)
            # wait() retorna True se o evento foi setado (parada),
            # False se o timeout expirou (normal — continuar loop)
            self._stop_event.wait(UNBAN_CHECK_INTERVAL)

        # ---- Encerramento: desbloquear todos os IPs ----
        # Quando o Agente encerra, removemos todas as regras do iptables
        # para não deixar IPs bloqueados permanentemente
        self._unban_all()

        # Log de encerramento
        logger.info("Thread BanManager encerrada.")

    def _check_expired_bans(self):
        """
        Verifica se algum ban ativo expirou e executa o desbloqueio.

        Para cada IP no dicionário de bans, compara o timestamp
        de unban com o tempo NTP atual. Se expirou, desbloqueia
        via iptables e remove do dicionário.
        """
        # Lista de IPs cujo ban expirou (para remoção posterior)
        expired_ips = []

        # ---- Seção crítica: iterar sobre o dicionário de bans ----
        with self._bans_lock:
            # Iterar sobre todos os bans ativos
            for ip, unban_time in self._active_bans.items():
                # Verificar se o ban expirou usando tempo NTP
                if is_ban_expired(unban_time, config.NTP_SERVER):
                    # Ban expirou — marcar para remoção
                    expired_ips.append(ip)

        # ---- Desbloquear IPs expirados (fora da seção crítica) ----
        for ip in expired_ips:
            # Log do desbloqueio automático
            logger.info(
                "AUTO-UNBAN: Ban do IP %s expirou. Desbloqueando...",
                ip,  # IP a desbloquear
            )

            # Executar desbloqueio no iptables
            unblock_ip(ip)

            # Remover do dicionário de bans ativos
            with self._bans_lock:
                # Usar pop() com default para evitar KeyError
                self._active_bans.pop(ip, None)

            # Log de sucesso
            logger.info(
                "AUTO-UNBAN: IP %s desbloqueado com sucesso.",
                ip,  # IP desbloqueado
            )

        # Log do total de bans ativos restantes (se houver)
        if expired_ips:
            with self._bans_lock:
                remaining = len(self._active_bans)
            logger.info(
                "Bans ativos restantes: %d",  # mensagem
                remaining,                     # quantidade
            )

    def _unban_all(self):
        """
        Desbloqueia TODOS os IPs banidos.
        Chamada durante o encerramento do Agente para limpar
        as regras de iptables.
        """
        # Seção crítica: acessar o dicionário de bans
        with self._bans_lock:
            # Se não há bans ativos, nada a fazer
            if not self._active_bans:
                logger.info("Nenhum ban ativo para limpar.")
                return

            # Copiar a lista de IPs antes de limpar
            ips_to_unban = list(self._active_bans.keys())

        # Desbloquear cada IP
        for ip in ips_to_unban:
            logger.info(
                "SHUTDOWN: Desbloqueando IP %s...",  # mensagem
                ip,                                   # IP
            )
            # Executar desbloqueio no iptables
            unblock_ip(ip)

        # Limpar o dicionário
        with self._bans_lock:
            self._active_bans.clear()

        # Log final
        logger.info(
            "SHUTDOWN: Todos os %d bans foram removidos.",
            len(ips_to_unban),  # quantidade removida
        )
