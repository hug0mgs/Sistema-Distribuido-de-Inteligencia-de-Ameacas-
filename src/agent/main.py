"""
main.py — Ponto de entrada do Agente (Nó Distribuído)

Orquestra a inicialização e o ciclo de vida de todas as threads:

  Thread 1 - LogMonitor:
      Monitora /var/log/auth.log em busca de tentativas falhas de SSH.
      Quando um IP atinge o limiar, enfileira um evento de ban.

  Thread 2 - NetworkListener:
      Mantém conexão TCP persistente com o Broker para receber
      alertas de broadcast (bans/unbans de outros Agentes).

  Thread 3 - HeartbeatSender:
      Envia pacotes UDP periódicos ao Broker como sinal de vida.

  Thread 4 - BanManager:
      Gerencia bloqueios via iptables e verifica periodicamente
      se há bans expirados para auto-unban (usando timestamps NTP).

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
        # Evento local — enviar ao Broker via conexão TCP temporária
        logger.info(
            "Evento local — enviando alerta ao Broker (%s:%d)...",
            config.BROKER_HOST,     # IP do Broker
            config.BROKER_TCP_PORT,  # porta do Broker
        )
        # send_alert_to_broker retorna True/False (sucesso/falha)
        success = send_alert_to_broker(
            event=event,                        # dados do evento
            broker_host=config.BROKER_HOST,     # IP do Broker
            broker_port=config.BROKER_TCP_PORT,  # porta do Broker
            agent_id=agent_id,                   # nosso identificador
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
      7. Entra em loop principal consumindo a fila de eventos
      8. Trata Ctrl+C para shutdown gracioso
    """
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

    # ---- Iniciar Thread 2: Escuta de Broadcasts TCP ----
    # O NetworkListener mantém uma conexão TCP persistente com o Broker
    # e coloca alertas recebidos (broadcast) na mesma ban_queue
    network_listener = NetworkListener(
        ban_queue=ban_queue,                # fila compartilhada
        broker_host=config.BROKER_HOST,     # IP do Broker
        broker_port=config.BROKER_TCP_PORT,  # porta TCP do Broker
        agent_id=agent_id,                   # nosso ID para registro
    )
    network_listener.start()  # chama NetworkListener.run() em thread separada
    logger.info("Thread NetworkListener iniciada (tid: %s)", network_listener.name)

    # ---- Iniciar Thread 3: Heartbeat UDP ----
    # Envia pacotes UDP periódicos ao Broker como sinal de vida.
    # O Broker usa esses pulsos para monitorar quais Agentes estão ativos.
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
        logger.info("Agente encerrado com sucesso.")


# ============================================================
# Ponto de entrada — execução direta do módulo
# ============================================================
if __name__ == "__main__":
    main()
