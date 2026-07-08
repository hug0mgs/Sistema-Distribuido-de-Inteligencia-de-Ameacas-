"""
main.py — Ponto de entrada do Agente (Nó Distribuído)

Orquestra a inicialização e o ciclo de vida de todas as threads:

  Thread 1 - LogMonitor:
      Monitora /var/log/auth.log em busca de tentativas falhas de SSH.
      Quando um IP atinge o limiar, enfileira um evento de ban.

  Thread 2 - NetworkListener:
      Mantém conexão TCP persistente com o Broker para receber
      alertas de broadcast (bans/unbans de outros Agentes).
      Se o Broker cair por mais de BROKER_FAILURE_TOLERANCE segundos,
      aciona a eleição de novo líder.

  Thread 3 - HeartbeatSender:
      Envia pacotes UDP periódicos ao Broker como sinal de vida.

  Thread 4 - BanManager:
      Gerencia bloqueios via iptables e verifica periodicamente
      se há bans expirados para auto-unban (usando timestamps NTP).

  Thread 5 - ElectionManager:
      Escuta mensagens de eleição UDP na porta ELECTION_UDP_PORT.
      Quando acionado (Broker morto), coordena a eleição via
      Bully Algorithm. Se vencer, inicia ThreatBroker interno
      (Broker Temporário). Mantém Recovery Probe tentando
      reconectar ao Broker original para failback.

  Thread Principal:
      Fica em loop consumindo a ban_queue. Quando há um evento LOCAL
      (do LogMonitor), executa o bloqueio e envia ao Broker via TCP.
      Quando há um evento de REDE (do NetworkListener), apenas aplica
      o bloqueio local (sem reenviar ao Broker — evita loop infinito).

Uso:
    sudo python -m agent.main
    sudo python -m agent.main --id agent-02

    (Requer sudo para ler /var/log/auth.log e executar iptables)
"""

# signal: captura Ctrl+C para encerramento gracioso
import signal

# sys: sys.exit() para encerrar e sys.argv para argumentos
import sys

# time: não usado diretamente aqui, mas disponível para futuras expansões
import time

# threading: locks para estado compartilhado do Broker
import threading

# logging: registro estruturado de eventos
import logging

# argparse: parser de argumentos de linha de comando
# Permite passar --id agent-02 ao iniciar o Agente
import argparse

# Queue: fila thread-safe; Empty: exceção quando a fila está vazia
from queue import Queue, Empty

# LogMonitor: thread que monitora o auth.log (Etapa 1)
from agent.log_monitor import LogMonitor

# NetworkListener: thread que escuta broadcasts do Broker via TCP
# send_alert_to_broker: função que envia alertas ao Broker
from agent.network import NetworkListener, send_alert_to_broker

# HeartbeatSender: thread que envia pulsos UDP ao Broker
from agent.heartbeat import HeartbeatSender

# BanManager: thread que gerencia bloqueios iptables e auto-unban NTP
from agent.firewall import BanManager

# ElectionManager: thread que coordena eleição de líder (Bully Algorithm)
from shared.election import ElectionManager

# config: configurações centralizadas do Agente
from agent import config

# ============================================================
# Configuração do Logging
# ============================================================
# Formato: [horário] [nível] [nome do módulo] mensagem
# Exemplo: [14:32:01] [WARNING] [agent.log_monitor] Falha de SSH detectada...
logging.basicConfig(
    level=logging.INFO,                                            # nível mínimo
    format="[%(asctime)s] [%(levelname)-8s] [%(name)s] %(message)s",  # formato
    datefmt="%H:%M:%S",                                            # formato hora
)
# Logger específico deste módulo
logger = logging.getLogger("agent.main")

# ============================================================
# Estado Mutável do Broker (compartilhado entre threads)
# ============================================================
# O endereço do Broker pode mudar dinamicamente durante uma eleição
# (apontar para o Broker Temporário) ou failback (voltar ao original).
# Protegido por lock para acesso thread-safe.
broker_state = {
    "host": config.BROKER_HOST,
    "tcp_port": config.BROKER_TCP_PORT,
    "udp_port": config.BROKER_UDP_PORT,
}
broker_state_lock = threading.Lock()

# Referência ao ThreatBroker interno (quando promovido a Broker Temporário)
# None = não somos Broker Temporário
_internal_broker = None
_internal_broker_lock = threading.Lock()


def handle_ban_event(event: dict, agent_id: str, ban_manager: BanManager):
    """
    Processa um evento de ban recebido da fila.

    Há duas origens possíveis para os eventos:
      1. LOCAL (do LogMonitor): detectado neste servidor → bloquear
         localmente E enviar ao Broker para broadcast.
      2. REDE (do NetworkListener): recebido via broadcast do Broker
         → apenas bloquear localmente (NÃO reenviar ao Broker, senão
         cria um loop infinito de mensagens).

    Args:
        event: dicionário com chaves 'action', 'ip', 'timestamp',
               'duration' e 'reason'.
        agent_id: identificador deste Agente.
        ban_manager: instância do BanManager para registrar bloqueios.
    """
    # Verificar a origem do evento (local ou rede)
    source = event.get("source", "local")

    # Log do processamento
    logger.critical(
        ">>> PROCESSANDO BAN [origem=%s]: IP=%s | Duração=%ds | Motivo=%s",
        source,                  # local ou network
        event["ip"],             # IP do atacante
        event["duration"],       # duração do ban em segundos
        event["reason"],         # motivo do ban
    )

    # ---- Bloqueio local via iptables (via BanManager) ----
    # O BanManager executa o iptables E agenda o auto-unban via NTP
    ban_manager.register_ban(
        ip=event["ip"],               # IP a bloquear
        ban_timestamp=event["timestamp"],  # timestamp NTP do ban
        ban_duration=event["duration"],    # duração em segundos
    )

    # ---- Enviar alerta ao Broker SOMENTE se for detecção LOCAL ----
    # Eventos de rede (recebidos via broadcast) NÃO devem ser reenviados
    # ao Broker, caso contrário cria-se um loop infinito:
    #   Agente A detecta → Broker → Agente B recebe → Broker → Agente A recebe → ...
    if source != "network":
        # Ler endereço atual do Broker (pode ter mudado após eleição)
        with broker_state_lock:
            current_host = broker_state["host"]
            current_port = broker_state["tcp_port"]

        # Evento local — enviar ao Broker via conexão TCP temporária
        logger.info(
            "Evento local — enviando alerta ao Broker (%s:%d)...",
            current_host,     # IP do Broker (pode ser temporário)
            current_port,     # porta do Broker
        )
        # send_alert_to_broker retorna True/False (sucesso/falha)
        success = send_alert_to_broker(
            event=event,                # dados do evento
            broker_host=current_host,   # IP do Broker (dinâmico)
            broker_port=current_port,   # porta do Broker
            agent_id=agent_id,          # nosso identificador
        )
        # Log do resultado
        if success:
            logger.info("Alerta enviado ao Broker com sucesso.")
        else:
            # Degradação graciosa: o ban local foi aplicado mesmo
            # sem conseguir avisar a rede
            logger.warning(
                "Falha ao enviar alerta ao Broker. "
                "O ban LOCAL foi aplicado, mas a rede NÃO foi notificada. "
                "(Degradação graciosa)"
            )
    else:
        # Evento de rede — apenas logar (já foi aplicado localmente acima)
        logger.info(
            "Evento de REDE — ban aplicado localmente. "
            "NÃO reenviado ao Broker (evitar loop)."
        )

    # TODO (futuro): agendar desbloqueio em rede (broadcast de unban)
    # Por enquanto o auto-unban é feito localmente pelo BanManager


def parse_args() -> argparse.Namespace:
    """
    Configura e processa argumentos de linha de comando.

    Argumentos disponíveis:
      --id: identificador único do Agente (padrão: "agent-01")
            Cada Agente na rede deve ter um ID diferente.

    Returns:
        Namespace com os argumentos processados.
    """
    # Criar o parser com descrição do programa
    parser = argparse.ArgumentParser(
        description="Agente do Sistema Distribuído de Inteligência de Ameaças",
    )
    # Argumento --id: identificador do Agente
    parser.add_argument(
        "--id",                          # nome do argumento
        default="agent-01",             # valor padrão
        help="Identificador único do Agente na rede (ex: agent-01, agent-02)",
    )
    # Processar e retornar os argumentos
    return parser.parse_args()


def main():
    """
    Função principal do Agente.

    Fluxo:
      1. Parseia argumentos de linha de comando (--id)
      2. Cria a fila thread-safe (ban_queue)
      3. Inicia Thread 1: LogMonitor (monitoramento de log)
      4. Inicia Thread 2: NetworkListener (escuta de broadcasts TCP)
      5. Inicia Thread 3: HeartbeatSender (pulsos UDP)
      6. Inicia Thread 4: BanManager (iptables + auto-unban NTP)
      7. Inicia Thread 5: ElectionManager (eleição de líder Bully)
      8. Entra em loop principal consumindo a fila de eventos
      9. Trata Ctrl+C para shutdown gracioso
    """
    # Referência global ao Broker interno (necessário nos callbacks)
    global _internal_broker

    # ---- Parsear argumentos da linha de comando ----
    args = parse_args()
    # O agent_id identifica este Agente perante o Broker e os demais
    agent_id = args.id

    # ---- Banner de inicialização ----
    logger.info("=" * 60)
    logger.info("AGENTE DE INTELIGÊNCIA DE AMEAÇAS — INICIANDO")
    logger.info("=" * 60)
    logger.info("ID do Agente: %s", agent_id)
    logger.info("Arquivo de log monitorado: %s", config.AUTH_LOG_PATH)
    logger.info("Limiar de ban: %d tentativas em %ds",
                config.MAX_FAILED_ATTEMPTS,    # número de tentativas
                config.FAILED_ATTEMPT_WINDOW)  # janela em segundos
    logger.info("Duração do ban: %ds", config.DEFAULT_BAN_DURATION)
    logger.info("Broker: %s:%d (TCP) / %s:%d (UDP)",
                config.BROKER_HOST,      # IP do Broker
                config.BROKER_TCP_PORT,  # porta TCP
                config.BROKER_HOST,      # IP do Broker
                config.BROKER_UDP_PORT)  # porta UDP
    logger.info("=" * 60)

    # ---- Fila thread-safe para comunicação inter-thread ----
    # A LogMonitor (produtora) e o NetworkListener (produtora)
    # colocam eventos aqui. O loop principal (consumidor) retira e processa.
    ban_queue: Queue = Queue()

    # ---- Iniciar Thread 1: Monitoramento de Log ----
    log_monitor = LogMonitor(ban_queue)
    log_monitor.start()  # chama LogMonitor.run() em thread separada
    logger.info("Thread LogMonitor iniciada (tid: %s)", log_monitor.name)

    # ---- Iniciar Thread 3: Heartbeat UDP ----
    # Envia pacotes UDP periódicos ao Broker como sinal de vida.
    # O Broker usa esses pulsos para monitorar quais Agentes estão ativos.
    # NOTA: iniciado ANTES do ElectionManager para que o update_broker
    # tenha uma referência válida.
    heartbeat_sender = HeartbeatSender(
        broker_host=config.BROKER_HOST,     # IP do Broker
        broker_port=config.BROKER_UDP_PORT,  # porta UDP do Broker
        agent_id=agent_id,                   # nosso ID
    )
    heartbeat_sender.start()  # chama HeartbeatSender.run() em thread separada
    logger.info("Thread HeartbeatSender iniciada (tid: %s)", heartbeat_sender.name)

    # ---- Iniciar Thread 4: Gerenciador de Bans (iptables + NTP) ----
    # O BanManager executa bloqueios via iptables e agenda desbloqueios
    # automáticos usando timestamps NTP para expiração precisa
    ban_manager = BanManager()
    ban_manager.start()  # chama BanManager.run() em thread separada
    logger.info("Thread BanManager iniciada (tid: %s)", ban_manager.name)

    # ================================================================
    # Callbacks de Eleição (chamados pelo ElectionManager)
    # ================================================================

    def on_promoted():
        """
        Callback: este Agente FOI ELEITO Broker Temporário.

        Ações:
          1. Importar e instanciar o ThreatBroker do módulo broker.main
          2. Iniciar o ThreatBroker em uma thread separada
          3. Atualizar broker_state para apontar para nós mesmos
          4. Atualizar NetworkListener e HeartbeatSender

        NOTA: Após a promoção, este Agente acumula funções:
          - Continua monitorando logs (LogMonitor)
          - Continua gerenciando firewall (BanManager)
          - TAMBÉM roda o ThreatBroker (aceita conexões e faz broadcast)
        """
        global _internal_broker

        logger.critical(
            ">>> PROMOÇÃO: Este Agente agora é o BROKER TEMPORÁRIO!"
        )

        # ---- Importar e instanciar ThreatBroker ----
        # Import dinâmico: só importamos quando realmente precisamos
        # (evita dependência circular e carrega sob demanda)
        from broker.main import ThreatBroker

        with _internal_broker_lock:
            _internal_broker = ThreatBroker()

        # ---- Iniciar ThreatBroker em thread separada ----
        # O ThreatBroker.start() bloqueia no accept loop, então
        # precisamos rodá-lo em uma thread própria
        broker_thread = threading.Thread(
            target=_internal_broker.start,
            daemon=True,
            name="InternalBrokerThread",
        )
        broker_thread.start()

        logger.info(
            "ThreatBroker interno iniciado em thread separada."
        )

        # ---- Atualizar broker_state para "eu mesmo" ----
        # Agora os alertas devem ser enviados para localhost
        # (o ThreatBroker interno está escutando nas mesmas portas)
        my_ip = election_manager._get_my_ip()
        with broker_state_lock:
            broker_state["host"] = my_ip
            broker_state["tcp_port"] = config.BROKER_TCP_PORT
            broker_state["udp_port"] = config.BROKER_UDP_PORT

        # ---- Atualizar NetworkListener e HeartbeatSender ----
        # Reconectar ao nosso ThreatBroker interno
        network_listener.update_broker(my_ip, config.BROKER_TCP_PORT)
        heartbeat_sender.update_broker(my_ip, config.BROKER_UDP_PORT)

        logger.info(
            "Broker state atualizado para %s (este Agente). "
            "NetworkListener e HeartbeatSender redirecionados.",
            my_ip,
        )

    def on_demoted():
        """
        Callback: o Broker original VOLTOU! (failback)

        Ações:
          1. Parar o ThreatBroker interno
          2. Restaurar broker_state para o Broker original
          3. Atualizar NetworkListener e HeartbeatSender
          4. Reconectar ao Broker original
        """
        global _internal_broker

        logger.critical(
            ">>> DEMOÇÃO: Broker original voltou! "
            "Parando ThreatBroker interno e reconectando ao original."
        )

        # ---- Parar o ThreatBroker interno ----
        with _internal_broker_lock:
            if _internal_broker is not None:
                # Fechar sockets do Broker interno
                try:
                    if _internal_broker._server_socket:
                        _internal_broker._server_socket.close()
                    if _internal_broker._udp_socket:
                        _internal_broker._udp_socket.close()
                    _internal_broker._disconnect_all_agents()
                except OSError:
                    pass  # Ignorar erros ao fechar

                _internal_broker = None
                logger.info("ThreatBroker interno parado com sucesso.")

        # ---- Restaurar broker_state para o original ----
        with broker_state_lock:
            broker_state["host"] = config.ORIGINAL_BROKER_HOST
            broker_state["tcp_port"] = config.BROKER_TCP_PORT
            broker_state["udp_port"] = config.BROKER_UDP_PORT

        # ---- Atualizar NetworkListener e HeartbeatSender ----
        # Reconectar ao Broker original
        network_listener.update_broker(
            config.ORIGINAL_BROKER_HOST,
            config.BROKER_TCP_PORT,
        )
        heartbeat_sender.update_broker(
            config.ORIGINAL_BROKER_HOST,
            config.BROKER_UDP_PORT,
        )

        logger.info(
            "Broker state restaurado para %s (original). "
            "Reconectando ao Broker original.",
            config.ORIGINAL_BROKER_HOST,
        )

    def on_new_leader(leader_id: str, leader_ip: str):
        """
        Callback: OUTRO Agente foi eleito Broker Temporário.

        Ações:
          1. Atualizar broker_state com o IP do novo líder
          2. Atualizar NetworkListener e HeartbeatSender para
             apontar para o novo Broker Temporário
        """
        logger.critical(
            ">>> NOVO LÍDER: Agente '%s' (IP: %s) é o Broker Temporário. "
            "Redirecionando conexões.",
            leader_id, leader_ip,
        )

        # ---- Atualizar broker_state ----
        with broker_state_lock:
            broker_state["host"] = leader_ip
            broker_state["tcp_port"] = config.BROKER_TCP_PORT
            broker_state["udp_port"] = config.BROKER_UDP_PORT

        # ---- Atualizar NetworkListener e HeartbeatSender ----
        network_listener.update_broker(leader_ip, config.BROKER_TCP_PORT)
        heartbeat_sender.update_broker(leader_ip, config.BROKER_UDP_PORT)

        logger.info(
            "Broker state atualizado para %s (Broker Temporário). "
            "Reconectando...",
            leader_ip,
        )

    # ---- Iniciar Thread 5: Eleição de Líder (Bully Algorithm) ----
    # O ElectionManager escuta mensagens de eleição UDP e,
    # quando acionado, coordena a eleição e o failback.
    election_manager = ElectionManager(
        agent_id=agent_id,
        election_port=config.ELECTION_UDP_PORT,
        election_timeout=config.ELECTION_TIMEOUT,
        original_broker_host=config.ORIGINAL_BROKER_HOST,
        original_broker_tcp_port=config.BROKER_TCP_PORT,
        recovery_probe_interval=config.RECOVERY_PROBE_INTERVAL,
        recovery_probe_max_duration=config.RECOVERY_PROBE_MAX_DURATION,
        on_promoted=on_promoted,
        on_demoted=on_demoted,
        on_new_leader=on_new_leader,
    )
    election_manager.start()
    logger.info("Thread ElectionManager iniciada (tid: %s)", election_manager.name)

    # ---- Iniciar Thread 2: Escuta de Broadcasts TCP ----
    # O NetworkListener mantém uma conexão TCP persistente com o Broker
    # e coloca alertas recebidos (broadcast) na mesma ban_queue.
    # Agora recebe o election_manager para acionar eleição se o Broker cair.
    network_listener = NetworkListener(
        ban_queue=ban_queue,                # fila compartilhada
        broker_host=config.BROKER_HOST,     # IP do Broker
        broker_port=config.BROKER_TCP_PORT,  # porta TCP do Broker
        agent_id=agent_id,                   # nosso ID para registro
        election_manager=election_manager,   # para acionar eleição
    )
    network_listener.start()  # chama NetworkListener.run() em thread separada
    logger.info("Thread NetworkListener iniciada (tid: %s)", network_listener.name)

    # ---- Handler de sinal para Ctrl+C (SIGINT) ----
    # Permite encerramento gracioso: para todas as threads antes de sair.
    def signal_handler(signum, frame):
        """Callback chamado quando o usuário pressiona Ctrl+C."""
        logger.info("\nSinal de interrupção recebido (Ctrl+C). Encerrando...")
        # Sinalizar parada para cada thread
        log_monitor.stop()          # parar monitoramento de log
        network_listener.stop()     # parar escuta de rede
        heartbeat_sender.stop()     # parar heartbeat UDP
        ban_manager.stop()          # parar gerenciador de bans (desbloqueia todos)
        election_manager.stop()     # parar eleição de líder

        # Se somos Broker Temporário, parar o ThreatBroker interno
        with _internal_broker_lock:
            if _internal_broker is not None:
                try:
                    if _internal_broker._server_socket:
                        _internal_broker._server_socket.close()
                    if _internal_broker._udp_socket:
                        _internal_broker._udp_socket.close()
                    _internal_broker._disconnect_all_agents()
                except OSError:
                    pass

        # Encerrar o programa
        sys.exit(0)

    # Registrar o handler para o sinal SIGINT (Ctrl+C)
    signal.signal(signal.SIGINT, signal_handler)

    # ---- Loop principal: consumir eventos da fila ----
    # Este loop roda na thread principal do programa.
    # Tanto o LogMonitor quanto o NetworkListener colocam eventos na fila.
    # O loop retira e processa cada um com handle_ban_event().
    #
    # Queue.get(timeout=1.0) bloqueia por até 1 segundo esperando um item.
    # Se não houver item, levanta queue.Empty e o loop continua — isso
    # permite checar o Ctrl+C periodicamente.
    logger.info("Agente pronto. Aguardando eventos de ban...")
    logger.info("Pressione Ctrl+C para encerrar.\n")

    try:
        # Loop infinito que consome a fila de eventos
        while True:
            try:
                # Tentar retirar um evento da fila (espera até 1s)
                event = ban_queue.get(timeout=1.0)
                # Processar o evento (bloqueio local + envio ao Broker)
                handle_ban_event(event, agent_id, ban_manager)
                # Marcar a tarefa como concluída na fila
                ban_queue.task_done()
            except Empty:
                # Nenhum evento na fila — isso é normal.
                # O loop volta e tenta de novo.
                continue

    except KeyboardInterrupt:
        # Captura Ctrl+C caso o signal handler não tenha sido acionado
        logger.info("Encerrando Agente...")
        log_monitor.stop()           # parar monitoramento de log
        network_listener.stop()      # parar escuta de rede
        heartbeat_sender.stop()      # parar heartbeat UDP
        ban_manager.stop()           # parar gerenciador de bans
        election_manager.stop()      # parar eleição de líder
        logger.info("Agente encerrado com sucesso.")


# ============================================================
# Ponto de entrada — execução direta do módulo
# ============================================================
if __name__ == "__main__":
    main()
