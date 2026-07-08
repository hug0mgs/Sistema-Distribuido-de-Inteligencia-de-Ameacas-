"""
election.py — Eleição de Líder via Bully Algorithm com Recovery Probe

PROBLEMA que este módulo resolve:
    O Broker central é um SPOF (Single Point of Failure). Se ele cair,
    os Agentes continuam protegendo localmente, mas perdem a capacidade
    de compartilhar inteligência de ameaças. Este módulo permite que
    os Agentes elejam um NOVO LÍDER automaticamente.

ALGORITMO — Bully Algorithm (Garcia-Molina, 1982):
    O "Algoritmo do Valentão" é um algoritmo clássico de eleição em
    sistemas distribuídos. Funciona assim:

      1. Um Agente detecta que o Broker caiu (falha na conexão TCP)
      2. Ele inicia uma ELEIÇÃO enviando "ELECTION" para todos os
         Agentes com ID MAIOR que o dele
      3. Se algum responde "OK" (eu tenho prioridade maior), o
         iniciador DESISTE e espera o resultado
      4. Se NENHUM responde (timeout), ele se declara o LÍDER
      5. O novo líder envia "COORDINATOR" para TODOS, informando
         quem é o novo Broker Temporário

    Por que "Valentão"? Porque o Agente com maior ID sempre "vence"
    a eleição — como um valentão que impõe sua vontade pelo tamanho.

BROKER TEMPORÁRIO com FAILBACK:
    O líder eleito NÃO assume permanentemente. Ele vira um Broker
    Temporário que:
      - Acumula funções: continua como Agente + roda ThreatBroker
      - Fica tentando reconectar ao Broker original (Recovery Probe)
      - Se o original voltar: envia "DEMOTION" e todos reconectam
      - Se o original não voltar em RECOVERY_PROBE_MAX_DURATION:
        assume o papel permanentemente

PROTOCOLO UDP P2P (porta 5602):
    Mensagens são JSONs enviados via UDP entre Agentes:
      - ELECTION:    "Quero iniciar uma eleição" (→ IDs maiores)
      - OK:          "Eu tenho ID maior, desista" (resposta a ELECTION)
      - COORDINATOR: "Eu sou o novo Broker" (→ todos)
      - DEMOTION:    "O Broker original voltou" (→ todos)

    UDP é ideal aqui porque:
      - Eleição é rara (só quando o Broker cai)
      - Mensagens são pequenas (poucos bytes)
      - Não precisa de conexão persistente (fire-and-forget)
      - Um único socket para enviar e receber de todos
"""

# socket: API de rede — UDP para comunicação P2P entre Agentes
import socket

# threading: threads para escuta UDP, eleição e recovery probe
import threading

# time: timestamps e timeouts
import time

# json: serialização das mensagens de eleição
import json

# logging: registro estruturado de eventos
import logging

# Logger específico deste módulo
logger = logging.getLogger(__name__)


class ElectionManager(threading.Thread):
    """
    Gerenciador de eleição de líder via Bully Algorithm.

    Esta thread escuta mensagens UDP de eleição na porta ELECTION_UDP_PORT
    e, quando acionada (trigger_election), coordena a eleição.

    Ciclo de vida do estado interno:
      IDLE → ELECTING → TEMP_BROKER → IDLE (failback)
                      → IDLE (outro venceu)

    Atributos:
        agent_id: identificador deste Agente (usado para prioridade)
        peers: lista de tuplas [(agent_id, ip)] dos outros Agentes
        _state: estado atual (IDLE, ELECTING, TEMP_BROKER)
        _on_promoted: callback quando ESTE Agente vira Broker Temporário
        _on_demoted: callback quando o Broker original volta (failback)
        _on_new_leader: callback quando OUTRO Agente vira Broker Temporário
        _stop_event: sinaliza encerramento da thread
    """

    # Constantes de estado
    STATE_IDLE = "IDLE"
    STATE_ELECTING = "ELECTING"
    STATE_TEMP_BROKER = "TEMP_BROKER"

    def __init__(
        self,
        agent_id: str,                          # ID deste Agente
        election_port: int,                     # porta UDP para eleição
        election_timeout: float,                # timeout para respostas OK
        original_broker_host: str,              # IP do Broker original
        original_broker_tcp_port: int,          # porta TCP do Broker original
        recovery_probe_interval: float,         # intervalo do recovery probe
        recovery_probe_max_duration: float,     # tempo máx. de recovery
        on_promoted: callable,                  # callback: eu virei Broker
        on_demoted: callable,                   # callback: Broker original voltou
        on_new_leader: callable,                # callback: outro virou Broker
    ):
        # daemon=True: thread morre com o programa principal
        super().__init__(daemon=True, name="ElectionManagerThread")

        # Identidade deste Agente
        self.agent_id = agent_id

        # Lista de peers: [(agent_id, ip_address), ...]
        # Preenchida dinamicamente via Service Discovery (update_peers)
        self.peers: list[tuple[str, str]] = []
        self._peers_lock = threading.Lock()

        # Configurações de rede e timeouts
        self._election_port = election_port
        self._election_timeout = election_timeout
        self._original_broker_host = original_broker_host
        self._original_broker_tcp_port = original_broker_tcp_port
        self._recovery_probe_interval = recovery_probe_interval
        self._recovery_probe_max_duration = recovery_probe_max_duration

        # Callbacks para notificar o main.py sobre mudanças de estado
        self._on_promoted = on_promoted      # eu virei Broker Temporário
        self._on_demoted = on_demoted        # Broker original voltou
        self._on_new_leader = on_new_leader  # outro Agente virou Broker

        # Estado interno da eleição
        self._state = self.STATE_IDLE
        self._state_lock = threading.Lock()

        # Flag: recebemos pelo menos um "OK" durante a eleição?
        # Se sim, alguém com ID maior vai assumir — desistimos
        self._received_ok = threading.Event()

        # Evento de parada para encerramento gracioso
        self._stop_event = threading.Event()

        # Socket UDP para comunicação P2P (criado em run())
        self._udp_socket: socket.socket | None = None

        # Thread do Recovery Probe (criada quando promovido a Broker)
        self._recovery_thread: threading.Thread | None = None
        self._recovery_stop = threading.Event()

    def stop(self):
        """Sinaliza para a thread encerrar na próxima iteração."""
        logger.info("Sinalizando parada da thread ElectionManager...")
        self._stop_event.set()
        # Parar recovery probe se estiver ativo
        self._recovery_stop.set()
        # Fechar o socket UDP para desbloquear recvfrom()
        if self._udp_socket:
            try:
                self._udp_socket.close()
            except OSError:
                pass

    def update_peers(self, new_peers: list[tuple[str, str]]):
        """
        Atualiza a lista de peers (Service Discovery).

        Chamado pelo NetworkListener quando o Broker envia um
        broadcast de atualização de topologia.
        """
        with self._peers_lock:
            self.peers = new_peers
        
        logger.info(
            "Topologia atualizada. Conhecemos %d peers agora.",
            len(new_peers),
        )

    def trigger_election(self):
        """
        Chamado pelo NetworkListener quando detecta que o Broker caiu
        (após BROKER_FAILURE_TOLERANCE segundos sem conexão).

        Inicia o processo de eleição em uma thread separada para não
        bloquear o chamador.
        """
        with self._state_lock:
            # Só iniciar eleição se estamos IDLE (evitar eleições duplicadas)
            if self._state != self.STATE_IDLE:
                logger.debug(
                    "Eleição já em andamento ou somos Broker Temporário. "
                    "Ignorando trigger duplicado."
                )
                return

            # Mudar estado para ELECTING
            self._state = self.STATE_ELECTING

        logger.critical(
            ">>> ELEIÇÃO INICIADA! Broker detectado como MORTO. "
            "Iniciando Bully Algorithm..."
        )

        # Executar a eleição em thread separada para não bloquear
        election_thread = threading.Thread(
            target=self._run_bully_election,
            daemon=True,
            name="BullyElectionThread",
        )
        election_thread.start()

    def run(self):
        """
        Loop principal: escuta mensagens UDP de eleição.

        Cria um socket UDP na porta ELECTION_UDP_PORT e fica em loop
        recebendo mensagens ELECTION, OK, COORDINATOR e DEMOTION.
        """
        logger.info(
            "Thread ElectionManager iniciada. "
            "Escutando mensagens de eleição na porta UDP %d",
            self._election_port,
        )

        # ---- Criar socket UDP para eleição ----
        self._udp_socket = socket.socket(
            socket.AF_INET,     # IPv4
            socket.SOCK_DGRAM,  # UDP (datagrama)
        )
        # Reutilizar porta imediatamente após reiniciar
        self._udp_socket.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1,
        )
        # Vincular a porta de eleição em todas as interfaces
        self._udp_socket.bind(("0.0.0.0", self._election_port))
        # Timeout para permitir verificação periódica do stop_event
        self._udp_socket.settimeout(2.0)

        # ---- Loop de escuta ----
        while not self._stop_event.is_set():
            try:
                # Receber pacote UDP (máx 1024 bytes — suficiente para JSON)
                data, addr = self._udp_socket.recvfrom(1024)

                # Decodificar JSON
                message = json.loads(data.decode("utf-8"))
                msg_type = message.get("type", "unknown")

                # Rotear por tipo de mensagem
                if msg_type == "election":
                    self._handle_election(message, addr)
                elif msg_type == "ok":
                    self._handle_ok(message, addr)
                elif msg_type == "coordinator":
                    self._handle_coordinator(message, addr)
                elif msg_type == "demotion":
                    self._handle_demotion(message, addr)
                else:
                    logger.warning(
                        "Mensagem de eleição desconhecida: %s", msg_type
                    )

            except socket.timeout:
                # Timeout normal — voltar ao loop
                continue

            except json.JSONDecodeError as e:
                logger.warning(
                    "Mensagem de eleição com JSON inválido: %s", e
                )

            except OSError:
                # Socket fechado (shutdown)
                if not self._stop_event.is_set():
                    logger.warning("Socket de eleição fechado inesperadamente.")
                break

        logger.info("Thread ElectionManager encerrada.")

    # ================================================================
    # Bully Algorithm — Lógica da Eleição
    # ================================================================

    def _run_bully_election(self):
        """
        Executa o Bully Algorithm.

        Passos:
          1. Resetar a flag _received_ok
          2. Enviar ELECTION para todos os peers com ID MAIOR
          3. Esperar ELECTION_TIMEOUT segundos por respostas OK
          4. Se recebeu OK → desistir (alguém maior vai assumir)
          5. Se NÃO recebeu OK → EU sou o líder!
             → Enviar COORDINATOR para todos
             → Chamar callback on_promoted
             → Iniciar Recovery Probe
        """
        # Resetar flag de resposta OK
        self._received_ok.clear()

        # Filtrar peers com ID MAIOR que o nosso (ordem lexicográfica)
        # No Bully Algorithm, só enviamos ELECTION para quem tem
        # prioridade MAIOR. Se nenhum deles responder, somos o maior.
        with self._peers_lock:
            higher_peers = [
                (pid, pip) for pid, pip in self.peers
                if pid > self.agent_id
            ]

        if higher_peers:
            # Enviar ELECTION para cada peer com ID maior
            logger.info(
                "Enviando ELECTION para %d peers com ID maior: %s",
                len(higher_peers),
                [pid for pid, _ in higher_peers],
            )
            for peer_id, peer_ip in higher_peers:
                self._send_election_message(
                    msg_type="election",
                    target_ip=peer_ip,
                    extra={"sender_id": self.agent_id},
                )

            # Esperar por respostas OK
            logger.info(
                "Aguardando respostas OK por %ds...",
                self._election_timeout,
            )
            got_ok = self._received_ok.wait(timeout=self._election_timeout)

            if got_ok:
                # Alguém com ID maior respondeu — desistir
                logger.info(
                    "Recebido OK de um peer com ID maior. "
                    "Desistindo da eleição e aguardando COORDINATOR."
                )
                # Voltar ao estado IDLE — vamos esperar o COORDINATOR
                # do peer que vai vencer
                with self._state_lock:
                    if self._state == self.STATE_ELECTING:
                        self._state = self.STATE_IDLE
                return
        else:
            logger.info(
                "Nenhum peer com ID maior que '%s'. "
                "Eu sou o de MAIOR prioridade!",
                self.agent_id,
            )

        # ---- Nenhum OK recebido ou ninguém maior existe ----
        # EU SOU O NOVO LÍDER!
        logger.critical(
            ">>> ELEIÇÃO VENCIDA! Agente '%s' é o novo Broker Temporário!",
            self.agent_id,
        )

        # Atualizar estado para Broker Temporário
        with self._state_lock:
            self._state = self.STATE_TEMP_BROKER

        # Enviar COORDINATOR para TODOS os peers
        # Informar que este Agente é o novo Broker
        my_ip = self._get_my_ip()
        with self._peers_lock:
            for peer_id, peer_ip in self.peers:
                self._send_election_message(
                    msg_type="coordinator",
                    target_ip=peer_ip,
                    extra={
                        "leader_id": self.agent_id,
                        "leader_ip": my_ip,
                    },
                )

        # Chamar callback de promoção (main.py vai iniciar ThreatBroker)
        logger.info("Chamando callback de promoção (on_promoted)...")
        self._on_promoted()

        # Iniciar Recovery Probe (tenta reconectar ao Broker original)
        self._start_recovery_probe()

    # ================================================================
    # Handlers de Mensagens
    # ================================================================

    def _handle_election(self, message: dict, addr: tuple):
        """
        Recebeu mensagem ELECTION de outro Agente.

        No Bully Algorithm, se recebemos ELECTION de alguém com ID
        MENOR, respondemos OK (dizendo "eu tenho prioridade maior,
        desista") e iniciamos NOSSA PRÓPRIA eleição.

        Args:
            message: dicionário com dados da mensagem
            addr: tupla (IP, porta) do remetente
        """
        sender_id = message.get("sender_id", "unknown")

        logger.info(
            "Recebido ELECTION do Agente '%s' (IP: %s:%d)",
            sender_id, addr[0], addr[1],
        )

        # Só responder se nosso ID é MAIOR que o do remetente
        if self.agent_id > sender_id:
            # Responder OK — "eu tenho prioridade maior"
            logger.info(
                "Meu ID '%s' > '%s'. Enviando OK e iniciando minha eleição.",
                self.agent_id, sender_id,
            )

            # Enviar OK para o remetente
            self._send_election_message(
                msg_type="ok",
                target_ip=addr[0],
                extra={"responder_id": self.agent_id},
            )

            # Iniciar nossa própria eleição (se ainda não estamos elegendo)
            self.trigger_election()
        else:
            # Nosso ID é menor — ignorar (não respondemos OK)
            logger.debug(
                "Meu ID '%s' < '%s'. Ignorando ELECTION.",
                self.agent_id, sender_id,
            )

    def _handle_ok(self, message: dict, addr: tuple):
        """
        Recebeu mensagem OK de outro Agente.

        Significa que existe alguém com ID maior que vai assumir.
        Devemos desistir da eleição.

        Args:
            message: dicionário com dados da mensagem
            addr: tupla (IP, porta) do remetente
        """
        responder_id = message.get("responder_id", "unknown")

        logger.info(
            "Recebido OK do Agente '%s' (IP: %s:%d). "
            "Ele tem prioridade maior — desistindo.",
            responder_id, addr[0], addr[1],
        )

        # Sinalizar que recebemos OK (a thread de eleição está esperando)
        self._received_ok.set()

    def _handle_coordinator(self, message: dict, addr: tuple):
        """
        Recebeu mensagem COORDINATOR — outro Agente venceu a eleição
        e é o novo Broker Temporário.

        Ações:
          1. Atualizar estado para IDLE
          2. Chamar callback on_new_leader (main.py vai reconectar)

        Args:
            message: dicionário com dados (leader_id, leader_ip)
            addr: tupla (IP, porta) do remetente
        """
        leader_id = message.get("leader_id", "unknown")
        leader_ip = message.get("leader_ip", addr[0])

        logger.critical(
            ">>> NOVO LÍDER ELEITO: Agente '%s' (IP: %s) "
            "é o Broker Temporário!",
            leader_id, leader_ip,
        )

        # Atualizar estado para IDLE (não somos o líder)
        with self._state_lock:
            self._state = self.STATE_IDLE

        # Notificar main.py para reconectar ao novo Broker
        self._on_new_leader(leader_id, leader_ip)

    def _handle_demotion(self, message: dict, addr: tuple):
        """
        Recebeu mensagem DEMOTION — o Broker original voltou!
        O Broker Temporário está se demitindo.

        Ações:
          1. Atualizar estado para IDLE
          2. Chamar callback on_demoted (main.py vai reconectar ao original)

        Args:
            message: dicionário com dados
            addr: tupla (IP, porta) do remetente
        """
        original_host = message.get("original_broker_host", "unknown")

        logger.critical(
            ">>> DEMOTION: Broker original voltou (IP: %s)! "
            "Reconectando ao Broker original.",
            original_host,
        )

        # Atualizar estado para IDLE
        with self._state_lock:
            self._state = self.STATE_IDLE

        # Notificar main.py para reconectar ao Broker original
        self._on_demoted()

    # ================================================================
    # Recovery Probe — Tenta reconectar ao Broker original
    # ================================================================

    def _start_recovery_probe(self):
        """
        Inicia a thread de Recovery Probe.

        Esta thread tenta reconectar ao Broker original periodicamente.
        Se o original voltar, envia DEMOTION para todos os peers e
        chama o callback on_demoted.
        """
        logger.info(
            "Iniciando Recovery Probe. "
            "Tentando reconectar ao Broker original (%s:%d) "
            "a cada %ds (máx %ds).",
            self._original_broker_host,
            self._original_broker_tcp_port,
            self._recovery_probe_interval,
            self._recovery_probe_max_duration,
        )

        # Resetar evento de parada do recovery
        self._recovery_stop.clear()

        # Criar e iniciar thread de recovery
        self._recovery_thread = threading.Thread(
            target=self._recovery_probe_loop,
            daemon=True,
            name="RecoveryProbeThread",
        )
        self._recovery_thread.start()

    def _recovery_probe_loop(self):
        """
        Loop do Recovery Probe.

        A cada RECOVERY_PROBE_INTERVAL segundos, tenta abrir uma conexão
        TCP com o Broker original. Se conseguir, o original voltou!

        Fluxo ao detectar que o original voltou:
          1. Enviar DEMOTION para todos os peers via UDP
          2. Chamar callback on_demoted (para o ThreatBroker interno)
          3. Atualizar estado para IDLE
        """
        # Marcar o momento de início para calcular tempo total
        start_time = time.time()

        # Contador de tentativas (para log)
        attempt = 0

        while not self._recovery_stop.is_set() and not self._stop_event.is_set():
            # Verificar se o tempo máximo de recovery foi atingido
            elapsed = time.time() - start_time
            if elapsed >= self._recovery_probe_max_duration:
                logger.warning(
                    "Recovery Probe: tempo máximo de %ds atingido. "
                    "Assumindo papel de Broker PERMANENTEMENTE.",
                    self._recovery_probe_max_duration,
                )
                # Parar de tentar — assumir permanentemente
                return

            # Incrementar contador de tentativas
            attempt += 1

            # Calcular tempo restante
            remaining = self._recovery_probe_max_duration - elapsed

            logger.info(
                "Recovery Probe: tentativa #%d. "
                "Tentando conectar ao Broker original (%s:%d). "
                "Tempo restante: %.0fs",
                attempt,
                self._original_broker_host,
                self._original_broker_tcp_port,
                remaining,
            )

            # Tentar conexão TCP com o Broker original
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                    # Timeout curto para não bloquear muito tempo
                    probe.settimeout(3.0)
                    # Tentar o three-way handshake TCP
                    probe.connect((
                        self._original_broker_host,
                        self._original_broker_tcp_port,
                    ))

                    # ============================================
                    # SUCESSO! O Broker original VOLTOU!
                    # ============================================
                    logger.critical(
                        ">>> BROKER ORIGINAL VOLTOU! "
                        "Conexão TCP com %s:%d bem-sucedida!",
                        self._original_broker_host,
                        self._original_broker_tcp_port,
                    )

                # Fechar a conexão de teste (saiu do 'with')

                # Enviar DEMOTION para todos os peers
                with self._peers_lock:
                    logger.info(
                        "Enviando DEMOTION para %d peers...",
                        len(self.peers),
                    )
                    for peer_id, peer_ip in self.peers:
                        self._send_election_message(
                            msg_type="demotion",
                            target_ip=peer_ip,
                            extra={
                                "original_broker_host": self._original_broker_host,
                            },
                        )

                # Atualizar estado para IDLE
                with self._state_lock:
                    self._state = self.STATE_IDLE

                # Chamar callback de demoção (main.py vai parar ThreatBroker)
                logger.info("Chamando callback de demoção (on_demoted)...")
                self._on_demoted()

                # Encerrar o loop de recovery
                return

            except (ConnectionRefusedError, TimeoutError, OSError) as e:
                # Broker original ainda fora — tentar de novo
                logger.debug(
                    "Recovery Probe: Broker original ainda fora: %s", e
                )

            # Esperar intervalo antes da próxima tentativa
            # Usar _recovery_stop.wait() para ser interrompível
            self._recovery_stop.wait(self._recovery_probe_interval)

        logger.info("Recovery Probe encerrado.")

    # ================================================================
    # Utilidades
    # ================================================================

    def _send_election_message(
        self,
        msg_type: str,      # tipo da mensagem (election, ok, coordinator, demotion)
        target_ip: str,      # IP do destinatário
        extra: dict = None,  # campos adicionais do JSON
    ):
        """
        Envia uma mensagem de eleição via UDP para um peer específico.

        Monta um dicionário JSON com o tipo da mensagem e campos extras,
        serializa em bytes UTF-8, e envia via sendto() no socket UDP.

        Args:
            msg_type: tipo da mensagem (election, ok, coordinator, demotion)
            target_ip: endereço IP do peer destinatário
            extra: campos adicionais para incluir no JSON
        """
        # Montar mensagem
        message = {"type": msg_type}
        if extra:
            message.update(extra)

        # Serializar e codificar
        payload = json.dumps(message).encode("utf-8")

        try:
            # Enviar via UDP (sendto — sem conexão prévia)
            if self._udp_socket:
                self._udp_socket.sendto(
                    payload,
                    (target_ip, self._election_port),
                )
                logger.debug(
                    "Mensagem '%s' enviada para %s:%d",
                    msg_type, target_ip, self._election_port,
                )
        except OSError as e:
            logger.warning(
                "Falha ao enviar mensagem '%s' para %s: %s",
                msg_type, target_ip, e,
            )

    def _get_my_ip(self) -> str:
        """
        Descobre o IP local desta máquina na rede.

        Técnica: abre um socket UDP (sem enviar nada) conectado a um
        IP externo e verifica qual IP local o SO escolheu. Funciona
        mesmo sem acesso real à internet — o SO apenas consulta a
        tabela de rotas.

        Returns:
            String com o IP local (ex: "192.168.1.101").
            Retorna "127.0.0.1" se não conseguir determinar.
        """
        try:
            # Criar socket UDP temporário
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                # Conectar a um IP externo (não envia dados — só consulta rota)
                s.connect(("8.8.8.8", 80))
                # Extrair o IP local que o SO escolheu
                local_ip = s.getsockname()[0]
            return local_ip
        except OSError:
            # Fallback: usar localhost
            logger.warning(
                "Não foi possível determinar IP local. Usando 127.0.0.1"
            )
            return "127.0.0.1"

    def get_state(self) -> str:
        """Retorna o estado atual da eleição (thread-safe)."""
        with self._state_lock:
            return self._state
