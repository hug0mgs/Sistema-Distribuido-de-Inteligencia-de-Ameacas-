"""
log_monitor.py — Thread de Monitoramento do auth.log

Esta thread implementa a técnica de "tail -f" em Python puro:
  1. Abre o arquivo de log
  2. Faz seek() até o final (ignora linhas antigas)
  3. Entra em loop infinito lendo novas linhas com readline()
  4. Se não há linha nova, dorme LOG_POLL_INTERVAL segundos e tenta de novo

Quando detecta uma falha de SSH, extrai o IP ofensor via regex e
incrementa um contador. Ao atingir MAX_FAILED_ATTEMPTS dentro da
janela de tempo, enfileira uma ação de "ban" na fila thread-safe.

CONCEITO DE REDE JUSTIFICADO:
  - threading.Thread: paralelismo real — esta thread roda independente
    da thread de rede, sem uma bloquear a outra.
  - queue.Queue: comunicação inter-thread segura (thread-safe). A thread
    de monitoramento PRODUZ eventos de ban; a thread de rede os CONSOME
    e transmite ao Broker via TCP (implementado na próxima etapa).
"""

import re
import time
import logging
import threading
from collections import defaultdict
from queue import Queue

# Configurações do Agente
from agent import config

# Módulo NTP para timestamps sincronizados globalmente
from shared.ntp_sync import get_ntp_time

# Logger específico deste módulo
logger = logging.getLogger(__name__)

# ============================================================
# Padrão regex para detectar falhas de autenticação SSH
# ============================================================
# Exemplos de linhas que casamcom este padrão:
#   "Failed password for root from 192.168.1.100 port 22 ssh2"
#   "Failed password for invalid user admin from 10.0.0.5 port 48230 ssh2"
#
# Grupo de captura (?P<ip>...): extrai o endereço IPv4 do atacante.
FAILED_SSH_PATTERN = re.compile(
    r"Failed password for .+ from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+"
)


class LogMonitor(threading.Thread):
    """
    Thread que monitora continuamente o arquivo auth.log em busca
    de tentativas falhas de login SSH.

    Atributos:
        ban_queue (Queue): fila thread-safe onde esta thread coloca
            dicionários {"ip": "x.x.x.x", "reason": "..."} quando
            um IP atinge o limiar de tentativas.
        _stop_event (threading.Event): sinaliza para a thread parar
            de forma graciosa (graceful shutdown).
    """

    def __init__(self, ban_queue: Queue):
        # daemon=True: a thread morre automaticamente quando o processo
        # principal termina. Sem isso, o programa ficaria pendurado.
        super().__init__(daemon=True, name="LogMonitorThread")

        self.ban_queue = ban_queue
        self._stop_event = threading.Event()

        # Dicionário: ip -> lista de timestamps de tentativas falhas
        # defaultdict(list) cria automaticamente uma lista vazia para
        # cada IP novo, evitando KeyError.
        self._failed_attempts: dict[str, list[float]] = defaultdict(list)

        # Conjunto de IPs já banidos localmente (evita banir duas vezes)
        self._banned_ips: set[str] = set()

    def stop(self):
        """Sinaliza para a thread encerrar na próxima iteração do loop."""
        logger.info("Sinalizando parada da thread LogMonitor...")
        self._stop_event.set()

    def run(self):
        """
        Método principal da thread — chamado automaticamente pelo
        threading.Thread.start().

        Implementa a lógica de "tail -f":
          - Abre o arquivo
          - Vai até o final (seek SEEK_END)
          - Lê novas linhas em loop
        """
        logger.info(
            "Thread LogMonitor iniciada. Monitorando: %s", config.AUTH_LOG_PATH
        )

        try:
            with open(config.AUTH_LOG_PATH, "r") as log_file:
                # ---- SEEK até o final do arquivo ----
                # Não queremos processar linhas antigas que já existiam
                # antes do Agente iniciar. Só nos interessam NOVAS linhas.
                # os.SEEK_END = 2 (posição relativa ao final do arquivo)
                log_file.seek(0, 2)
                logger.info(
                    "Seek realizado até o final do arquivo. "
                    "Aguardando novas entradas de log..."
                )

                # ---- Loop principal de leitura ----
                while not self._stop_event.is_set():
                    line = log_file.readline()

                    if line:
                        # Linha nova disponível — processar
                        self._process_line(line.strip())
                    else:
                        # Nenhuma linha nova — dormir e tentar de novo.
                        # Esse sleep é o que torna o polling eficiente:
                        # sem ele, o loop consumiria 100% de CPU.
                        time.sleep(config.LOG_POLL_INTERVAL)

        except FileNotFoundError:
            logger.error(
                "Arquivo de log não encontrado: %s. "
                "Verifique se o caminho está correto e se o SSH está "
                "instalado neste servidor.",
                config.AUTH_LOG_PATH,
            )
        except PermissionError:
            logger.error(
                "Sem permissão para ler %s. "
                "Execute o Agente com sudo ou adicione o usuário ao "
                "grupo 'adm': sudo usermod -aG adm $USER",
                config.AUTH_LOG_PATH,
            )

        logger.info("Thread LogMonitor encerrada.")

    def _process_line(self, line: str):
        """
        Analisa uma linha do auth.log. Se contiver uma falha de SSH,
        registra a tentativa e verifica se o IP atingiu o limiar de ban.

        Args:
            line: linha de texto já sem whitespace nas extremidades.
        """
        match = FAILED_SSH_PATTERN.search(line)
        if not match:
            return  # Linha irrelevante (login bem-sucedido, sudo, etc.)

        ip = match.group("ip")
        now = time.time()

        logger.warning("Falha de SSH detectada do IP: %s", ip)

        # Se já está banido, não precisamos contar de novo
        if ip in self._banned_ips:
            logger.debug("IP %s já está banido. Ignorando.", ip)
            return

        # Registrar o timestamp desta tentativa
        self._failed_attempts[ip].append(now)

        # ---- Limpar tentativas antigas (fora da janela de tempo) ----
        # Mantém apenas as tentativas que ocorreram nos últimos
        # FAILED_ATTEMPT_WINDOW segundos. Isso impede que 5 tentativas
        # espalhadas ao longo de 1 semana disparem um ban.
        cutoff = now - config.FAILED_ATTEMPT_WINDOW
        self._failed_attempts[ip] = [
            t for t in self._failed_attempts[ip] if t > cutoff
        ]

        attempts = len(self._failed_attempts[ip])
        remaining = config.MAX_FAILED_ATTEMPTS - attempts

        logger.info(
            "IP %s: %d/%d tentativas (restam %d antes do ban)",
            ip,
            attempts,
            config.MAX_FAILED_ATTEMPTS,
            max(remaining, 0),
        )

        # ---- Verificar se atingiu o limiar ----
        if attempts >= config.MAX_FAILED_ATTEMPTS:
            self._trigger_ban(ip)

    def _trigger_ban(self, ip: str):
        """
        Dispara a ação de banimento para um IP.

        1. Adiciona o IP ao conjunto de banidos (evita duplicatas)
        2. Limpa o contador de tentativas
        3. Coloca o evento de ban na fila thread-safe (ban_queue)

        A thread de rede (a ser implementada) consumirá esta fila
        e enviará o alerta ao Broker via TCP.

        Args:
            ip: endereço IPv4 do atacante.
        """
        logger.critical(
            "LIMIAR ATINGIDO! Banindo IP: %s (%d tentativas em %ds)",
            ip,
            config.MAX_FAILED_ATTEMPTS,
            config.FAILED_ATTEMPT_WINDOW,
        )

        self._banned_ips.add(ip)
        del self._failed_attempts[ip]

        # Evento de ban para a fila inter-thread
        # IMPORTANTE: o timestamp vem do NTP (tempo global), NÃO do
        # relógio local. Isso garante que todos os Agentes calculem
        # o mesmo momento de unban, independente do clock drift.
        ntp_timestamp = get_ntp_time(config.NTP_SERVER)

        ban_event = {
            "action": "ban",
            "ip": ip,
            "timestamp": ntp_timestamp,  # timestamp NTP sincronizado
            "duration": config.DEFAULT_BAN_DURATION,
            "reason": f"{config.MAX_FAILED_ATTEMPTS} falhas de SSH "
                      f"em {config.FAILED_ATTEMPT_WINDOW}s",
        }

        # Queue.put() é THREAD-SAFE — múltiplas threads podem
        # escrever/ler sem corromper dados.
        self.ban_queue.put(ban_event)

        logger.info("Evento de ban enfileirado: %s", ban_event)

        # TODO (Próxima etapa): executar bloqueio local via iptables
        # subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
