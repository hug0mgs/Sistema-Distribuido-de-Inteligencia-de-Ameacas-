"""
network.py — Módulo de Rede do Agente (Sockets TCP)

Este módulo contém:

  1. NetworkListener (Thread):
       Mantém uma conexão TCP persistente com o Broker.
       Fica escutando mensagens de broadcast (bans/unbans que outros
       Agentes detectaram). Quando recebe um alerta, coloca na
       ban_queue para o loop principal processar.

       INTEGRAÇÃO COM ELEIÇÃO:
       Se a conexão com o Broker falhar por mais de
       BROKER_FAILURE_TOLERANCE segundos, aciona o ElectionManager
       para iniciar uma eleição de novo líder via Bully Algorithm.

  2. send_alert_to_broker (Função):
       Chamada pelo loop principal quando o LogMonitor detecta um
       ataque local. Abre uma conexão TCP temporária com o Broker,
       envia o alerta, e fecha a conexão.

DECISÃO DE DESIGN — Por que duas conexões TCP separadas?
    - NetworkListener: conexão PERSISTENTE (long-lived) — fica aberta
      o tempo todo para receber broadcasts em tempo real.
    - send_alert_to_broker: conexão TEMPORÁRIA (short-lived) — abre,
      envia, fecha. Mais simples e tolerante a falhas.

    Na prática profissional, usaríamos uma única conexão bidirecional.
    Mas para fins didáticos, separar facilita entender os dois padrões
    de comunicação TCP: persistente vs. sob demanda.

CONCEITOS DE REDE JUSTIFICADOS:
    - socket.socket(AF_INET, SOCK_STREAM): cria socket TCP/IPv4
    - AF_INET = família de endereços IPv4
    - SOCK_STREAM = protocolo orientado a conexão (TCP)
    - connect() = three-way handshake TCP (SYN → SYN-ACK → ACK)
"""

# socket: API de rede de baixo nível — sockets TCP/UDP
import socket

# threading: criação de threads para paralelismo
import threading

# time: sleep para reconexão e timestamps
import time

# logging: registro estruturado de eventos
import logging

# Queue: fila thread-safe para comunicação entre threads
from queue import Queue

# Importar nosso protocolo de mensagens length-prefix
from shared.protocol import send_message, receive_message

# Importar configurações do Agente
from agent import config

# Logger específico deste módulo
logger = logging.getLogger(__name__)


class NetworkListener(threading.Thread):
    """
    Thread que mantém conexão TCP persistente com o Broker para
    receber alertas de broadcast (bans/unbans de outros Agentes).

    Fluxo:
      1. Conecta ao Broker via TCP (three-way handshake)
      2. Envia mensagem de registro ("sou um Agente, me inclua no broadcast")
      3. Entra em loop recebendo mensagens via protocolo length-prefix
      4. Para cada mensagem recebida, coloca na ban_queue
      5. Se a conexão cair, tenta reconectar após N segundos
      6. Se falhar por mais de BROKER_FAILURE_TOLERANCE, aciona eleição

    Atributos:
        ban_queue: fila onde coloca alertas recebidos do Broker
        broker_host: endereço IP do Broker (pode mudar após eleição)
        broker_port: porta TCP do Broker
        agent_id: identificador único deste Agente na rede
        election_manager: referência ao ElectionManager para acionar eleição
        _stop_event: sinaliza para a thread parar
    """

    def __init__(
        self,
        ban_queue: Queue,       # fila thread-safe para eventos recebidos
        broker_host: str,       # IP do Broker (ex: "192.168.1.10")
        broker_port: int,       # porta TCP do Broker (ex: 5600)
        agent_id: str,          # identificador deste Agente (ex: "agent-01")
        election_manager=None,  # referência ao ElectionManager (opcional)
    ):
        # daemon=True: thread morre quando o programa principal encerra
        # name: nome legível para identificar a thread em logs/debug
        super().__init__(daemon=True, name="NetworkListenerThread")

        # Armazenar parâmetros como atributos da instância
        self.ban_queue = ban_queue      # fila para repassar alertas recebidos
        self.broker_host = broker_host  # endereço do Broker
        self.broker_port = broker_port  # porta do Broker
        self.agent_id = agent_id        # ID deste Agente

        # Referência ao ElectionManager para acionar eleição
        # quando o Broker cair por tempo suficiente
        # [DESATIVADO] self.election_manager = election_manager
        self.election_manager = None

        # Lock para acesso thread-safe ao broker_host e broker_port.
        # Necessário porque o ElectionManager pode chamar update_broker()
        # de outra thread durante uma eleição ou failback.
        self._broker_lock = threading.Lock()

        # Evento de parada para encerramento gracioso
        self._stop_event = threading.Event()

        # Evento de reconexão forçada: sinalizado por update_broker()
        # para interromper imediatamente o delay de reconexão e
        # forçar uma nova tentativa com o endereço atualizado.
        self._reconnect_event = threading.Event()

        # Intervalo entre tentativas de reconexão (em segundos)
        self._reconnect_delay = 5

        # Timestamp da primeira falha consecutiva de conexão.
        # Usado para calcular se já passamos de BROKER_FAILURE_TOLERANCE.
        # None = sem falha ativa (conexão está OK)
        self._first_failure_time: float | None = None

        # Flag para evitar acionar a eleição múltiplas vezes
        # [DESATIVADO] self._election_triggered = False

    def stop(self):
        """Sinaliza para a thread encerrar na próxima iteração."""
        # Marcar o evento de parada como "setado"
        logger.info("Sinalizando parada da thread NetworkListener...")
        self._stop_event.set()

    def update_broker(self, new_host: str, new_port: int):
        """
        Atualiza o endereço do Broker para uma nova localização.

        Chamado pelo main.py quando:
          - Um novo Broker Temporário é eleito (eleição)
          - O Broker original volta (failback / demotion)

        Thread-safe: usa lock para proteger a atualização.
        Também reseta os contadores de falha para permitir
        reconexão imediata ao novo Broker.

        Args:
            new_host: novo IP do Broker.
            new_port: nova porta TCP do Broker.
        """
        with self._broker_lock:
            old_host = self.broker_host
            self.broker_host = new_host
            self.broker_port = new_port

        # Resetar contadores de falha (novo Broker, novas chances)
        self._first_failure_time = None
        # [DESATIVADO] self._election_triggered = False

        # Sinalizar reconexão forçada para interromper o delay atual
        # e forçar o loop a tentar conectar ao novo endereço imediatamente
        self._reconnect_event.set()

        logger.info(
            "NetworkListener: destino atualizado de %s para %s:%d",
            old_host, new_host, new_port,
        )

    def run(self):
        """
        Método principal da thread. Executado ao chamar .start().

        Implementa um loop de conexão com reconexão automática:
        se a conexão com o Broker cair, espera alguns segundos e
        tenta conectar de novo (tolerância a falhas).

        INTEGRAÇÃO COM ELEIÇÃO:
        Se a conexão falhar continuamente por mais de
        BROKER_FAILURE_TOLERANCE segundos, aciona o ElectionManager
        para iniciar uma eleição de novo líder.
        """
        logger.info(
            "Thread NetworkListener iniciada. "  # mensagem informativa
            "Broker: %s:%d",                     # endereço do Broker
            self.broker_host,                    # IP
            self.broker_port,                    # porta
        )

        # ---- Loop externo: reconexão automática ----
        # Se a conexão cair, este loop garante que tentamos de novo
        while not self._stop_event.is_set():
            try:
                # Tentar conectar e escutar mensagens do Broker
                self._connect_and_listen()

                # Se chegou aqui, a conexão foi bem-sucedida em algum
                # momento. Resetar contadores de falha.
                self._first_failure_time = None
                # [DESATIVADO] self._election_triggered = False

            except ConnectionRefusedError:
                # Broker não está rodando ou recusou a conexão
                logger.warning(
                    "Conexão recusada pelo Broker (%s:%d). "  # mensagem
                    "Tentando novamente em %ds...",            # aviso
                    self.broker_host,                          # IP
                    self.broker_port,                          # porta
                    self._reconnect_delay,                    # delay
                )
                # Registrar falha e verificar se devemos acionar eleição
                self._check_failure_tolerance()

            except ConnectionResetError:
                # Broker fechou a conexão abruptamente (crash, reinício)
                logger.warning(
                    "Conexão resetada pelo Broker. "  # mensagem
                    "Tentando reconectar em %ds...",   # aviso
                    self._reconnect_delay,             # delay
                )
                # Registrar falha e verificar se devemos acionar eleição
                self._check_failure_tolerance()

            except OSError as e:
                # Outro erro de rede (timeout, rede inacessível, etc.)
                logger.error(
                    "Erro de rede: %s. "              # mensagem com o erro
                    "Tentando reconectar em %ds...",   # aviso
                    e,                                 # detalhes do erro
                    self._reconnect_delay,             # delay
                )
                # Registrar falha e verificar se devemos acionar eleição
                self._check_failure_tolerance()

            # ---- Esperar antes de reconectar ----
            # Usamos _stop_event.wait() em vez de time.sleep() porque:
            # - time.sleep(5) bloqueia 5 segundos INCONDICIONALMENTE
            # - _stop_event.wait(5) retorna IMEDIATAMENTE se stop() for
            #   chamado, permitindo encerramento rápido
            # Também verificamos _reconnect_event: se update_broker() for
            # chamado (ex: após eleição), acordamos imediatamente para
            # conectar ao novo Broker sem esperar o delay completo.
            if not self._stop_event.is_set() and not self._reconnect_event.is_set():
                self._stop_event.wait(self._reconnect_delay)

            # Limpar o evento de reconexão (já foi consumido)
            self._reconnect_event.clear()

        # Thread encerrada
        logger.info("Thread NetworkListener encerrada.")

    def _check_failure_tolerance(self):
        """
        Verifica se o tempo de falha consecutiva ultrapassou o
        BROKER_FAILURE_TOLERANCE. Se sim, aciona a eleição.

        Lógica:
          - Na primeira falha, registra o timestamp em _first_failure_time
          - Nas falhas seguintes, calcula o tempo total de falha
          - Se ultrapassou BROKER_FAILURE_TOLERANCE, aciona eleição
          - A eleição só é acionada UMA VEZ (_election_triggered)
        """
        # Registrar a primeira falha
        if self._first_failure_time is None:
            self._first_failure_time = time.time()
            logger.info(
                "Primeira falha de conexão com o Broker registrada. "
                "Tolerância: %ds",
                config.BROKER_FAILURE_TOLERANCE,
            )
            return

        # Calcular tempo total de falha
        elapsed = time.time() - self._first_failure_time

        logger.info(
            "Falha de conexão contínua há %.0fs "
            "(tolerância: %ds)",
            elapsed,
            config.BROKER_FAILURE_TOLERANCE,
        )

        # Verificar se ultrapassou a tolerância
        """
        [DESATIVADO] Lógica de eleição
        if elapsed >= config.BROKER_FAILURE_TOLERANCE and not self._election_triggered:
            # Marcar como acionada para não disparar várias vezes
            self._election_triggered = True

            logger.critical(
                ">>> BROKER CONSIDERADO MORTO após %.0fs sem conexão! "
                "Acionando eleição de novo líder...",
                elapsed,
            )

            # Acionar eleição via ElectionManager
            if self.election_manager:
                self.election_manager.trigger_election()
            else:
                logger.warning(
                    "ElectionManager não configurado. "
                    "Não é possível iniciar eleição."
                )
        """

    def _connect_and_listen(self):
        """
        Conecta ao Broker e entra em loop de recebimento de mensagens.

        Passos:
          1. Criar socket TCP
          2. Conectar ao Broker (three-way handshake)
          3. Enviar mensagem de registro
          4. Loop de recebimento de mensagens
        """
        # ---- Ler endereço do Broker (thread-safe) ----
        # O endereço pode mudar dinamicamente após eleição/failback
        with self._broker_lock:
            current_host = self.broker_host
            current_port = self.broker_port

        # ---- Passo 1: Criar socket TCP/IPv4 ----
        # AF_INET  = família de endereços IPv4 (ex: 192.168.1.1)
        # SOCK_STREAM = protocolo orientado a stream/conexão = TCP
        # 'with' garante que o socket é fechado ao sair do bloco
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:

            # ---- Passo 2: Conectar ao Broker ----
            # connect() realiza o three-way handshake TCP:
            #   1. Agente → Broker: SYN (pedido de conexão)
            #   2. Broker → Agente: SYN-ACK (aceite + confirmação)
            #   3. Agente → Broker: ACK (confirmação final)
            # Após isso, a conexão TCP está estabelecida.
            logger.info(
                "Conectando ao Broker em %s:%d...",  # log da tentativa
                current_host,                        # IP destino
                current_port,                        # porta destino
            )
            sock.connect((current_host, current_port))
            logger.info("Conectado ao Broker com sucesso!")

            # Conexão bem-sucedida — resetar contadores de falha
            self._first_failure_time = None
            self._election_triggered = False

            # ---- Passo 3: Enviar mensagem de REGISTRO ----
            # Informa ao Broker que este é um Agente que deseja
            # receber broadcasts. O Broker armazena esta conexão
            # na sua lista de clientes.
            register_msg = {
                "type": "register",             # tipo da mensagem
                "agent_id": self.agent_id,      # identificador deste Agente
            }
            # Usar nosso protocolo length-prefix para enviar
            send_message(sock, register_msg)
            logger.info(
                "Mensagem de registro enviada: agent_id=%s",  # log
                self.agent_id,                                # ID enviado
            )

            # ---- Passo 4: Loop de recebimento de mensagens ----
            # Fica bloqueado em receive_message() até receber dados
            # ou a conexão ser fechada
            while not self._stop_event.is_set():
                # receive_message() retorna dict ou None (desconexão)
                message = receive_message(sock)

                # Se retornou None, a conexão foi fechada pelo Broker
                if message is None:
                    logger.warning(
                        "Broker encerrou a conexão. "  # aviso
                        "Saindo do loop de escuta."    # ação
                    )
                    # Sair do loop interno → volta ao loop externo
                    # que tentará reconectar
                    break

                # ---- Roteamento da Mensagem ----
                msg_type = message.get("type", "unknown")

                if msg_type == "peer_update":
                    # SERVICE DISCOVERY: Atualização da topologia da rede
                    logger.info("Recebida atualização de topologia (Service Discovery).")
                    if self.election_manager:
                        peers_list = message.get("peers", [])
                        self.election_manager.update_peers(peers_list)
                    continue  # Volta ao loop, não coloca na fila de bans

                # Mensagem de alerta de ban recebida com sucesso — processar
                logger.info(
                    "Alerta recebido do Broker: %s",  # log do alerta
                    message,                          # conteúdo da mensagem
                )

                # Colocar na ban_queue para o loop principal processar
                # Marcamos a origem como "rede" para distinguir de
                # alertas locais (detectados pelo LogMonitor)
                message["source"] = "network"
                self.ban_queue.put(message)


def send_alert_to_broker(
    event: dict,          # evento de ban/unban a ser enviado
    broker_host: str,     # IP do Broker
    broker_port: int,     # porta TCP do Broker
    agent_id: str,        # identificador deste Agente
) -> bool:
    """
    Envia um alerta de ban/unban ao Broker via conexão TCP temporária.

    Esta função é chamada pelo loop principal (thread principal) quando
    o LogMonitor detecta um ataque. A conexão é aberta, o alerta é
    enviado, e a conexão é fechada logo em seguida.

    Padrão de conexão: SHORT-LIVED (curta duração)
    - Abre → envia → fecha
    - Simples e tolerante a falhas (se falhar, não afeta outras partes)
    - Cada alerta é independente

    Args:
        event: dicionário com dados do ban (ip, action, timestamp, etc.)
        broker_host: endereço IP do Broker
        broker_port: porta TCP do Broker
        agent_id: identificador deste Agente

    Returns:
        True se o alerta foi enviado com sucesso, False caso contrário.
    """
    try:
        # ---- Criar socket TCP e conectar ao Broker ----
        # 'with' garante fechamento automático do socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:

            # Definir timeout de 5 segundos para a conexão
            # Se o Broker não responder em 5s, levanta TimeoutError
            sock.settimeout(5.0)

            # Conectar ao Broker (three-way handshake TCP)
            sock.connect((broker_host, broker_port))

            # ---- Montar mensagem de alerta ----
            # Adicionar metadados de origem ao evento
            alert_msg = {
                "type": "alert",               # tipo: alerta de ameaça
                "agent_id": agent_id,           # quem detectou o ataque
                **event,                        # desempacota os dados do evento
                                                # (action, ip, timestamp, duration, reason)
            }

            # ---- Enviar pelo protocolo length-prefix ----
            send_message(sock, alert_msg)

            # Log de sucesso
            logger.info(
                "Alerta enviado ao Broker com sucesso: "  # mensagem
                "action=%s, ip=%s",                       # detalhes
                event.get("action"),                      # ban ou unban
                event.get("ip"),                          # IP do atacante
            )

            # Retornar True indicando sucesso
            return True

    except ConnectionRefusedError:
        # Broker não está rodando — log de aviso
        logger.warning(
            "Falha ao enviar alerta: Broker (%s:%d) "  # mensagem
            "recusou a conexão.",                       # detalhes
            broker_host,                               # IP
            broker_port,                               # porta
        )
        # Retornar False indicando falha (degradação graciosa)
        return False

    except TimeoutError:
        # Broker não respondeu a tempo — log de aviso
        logger.warning(
            "Falha ao enviar alerta: timeout ao conectar "  # mensagem
            "ao Broker (%s:%d).",                            # detalhes
            broker_host,                                     # IP
            broker_port,                                     # porta
        )
        # Retornar False indicando falha
        return False

    except OSError as e:
        # Outro erro de rede — log de erro com detalhes
        logger.error(
            "Falha ao enviar alerta ao Broker: %s",  # mensagem
            e,                                        # detalhes do erro
        )
        # Retornar False indicando falha
        return False
