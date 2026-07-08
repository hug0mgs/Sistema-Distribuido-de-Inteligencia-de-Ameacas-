"""
broker/main.py — Servidor Broker (Coordenação Pub/Sub)

O Broker é o nó central do modelo Publish/Subscribe. Ele NÃO processa
dados nem toma decisões — apenas RETRANSMITE mensagens.

Responsabilidades:
  1. Aceitar conexões TCP de Agentes (registros e alertas)
  2. Quando recebe um alerta de um Agente, fazer BROADCAST (repassar)
     para todos os OUTROS Agentes conectados
  3. Receber heartbeats UDP para monitorar disponibilidade dos Agentes

ARQUITETURA DE THREADS DO BROKER:
  - Thread Principal: aceita novas conexões TCP (accept loop)
  - Thread HeartbeatListener: escuta pacotes UDP de heartbeat
  - Thread por Agente registrado: mantém a conexão persistente aberta
    para poder enviar broadcasts a qualquer momento
  - Thread por alerta recebido: processa alertas em conexões curtas

CONCEITOS DE REDE JUSTIFICADOS:
  - bind(): associa o socket a um endereço IP e porta
  - listen(): coloca o socket em modo de escuta (passivo)
  - accept(): bloqueia até um cliente conectar (three-way handshake)
  - SO_REUSEADDR: permite reutilizar a porta imediatamente após reiniciar
    (sem isso, o SO bloqueia a porta por ~60s após fechar o programa)
  - recvfrom(): recebe pacote UDP com endereço do remetente
  - SOCK_DGRAM: socket UDP para heartbeats (sem conexão, leve)

Uso:
    python -m broker.main

    (Não requer sudo — o Broker não acessa firewall nem logs do sistema)
"""

# socket: API de rede de baixo nível
import socket

# threading: uma thread por cliente registrado + lock para lista compartilhada
import threading

# logging: registro estruturado de eventos
import logging

# sys: encerramento do programa
import sys

# signal: tratamento de Ctrl+C
import signal

# json: deserialização dos pacotes UDP de heartbeat
import json

# time: timestamps para cálculo de inatividade dos Agentes
import time

# Nosso protocolo de mensagens TCP (length-prefix JSON)
from shared.protocol import send_message, receive_message

# ============================================================
# Configuração do Logging
# ============================================================
# Formato padronizado com timestamp, nível e nome do módulo
logging.basicConfig(
    level=logging.INFO,                                           # nível mínimo: INFO
    format="[%(asctime)s] [%(levelname)-8s] [%(name)s] %(message)s",  # formato
    datefmt="%H:%M:%S",                                           # formato do horário
)
# Logger específico do Broker
logger = logging.getLogger("broker.main")

# ============================================================
# Configurações do Broker
# ============================================================
# Endereço de escuta: "0.0.0.0" aceita conexões de QUALQUER interface
# de rede (não apenas localhost). Necessário para receber de outras VMs.
BROKER_BIND_HOST = "0.0.0.0"

# Porta TCP para alertas e registros
BROKER_TCP_PORT = 5600

# Porta UDP para recebimento de heartbeats dos Agentes
BROKER_UDP_PORT = 5601

# Tempo máximo (em segundos) sem heartbeat antes de considerar
# um Agente como inativo/morto. Se um Agente não envia heartbeat
# por mais de HEARTBEAT_TIMEOUT segundos, é marcado como inativo.
HEARTBEAT_TIMEOUT = 60


class ThreatBroker:
    """
    Servidor Broker do sistema Pub/Sub de inteligência de ameaças.

    Mantém uma lista de Agentes registrados (conexões TCP persistentes)
    e, quando recebe um alerta, faz broadcast para todos os outros.

    Atributos:
        _registered_agents: dicionário de conexões persistentes
            {agent_id: socket} — protegido por lock
        _agents_lock: threading.Lock para acesso thread-safe ao dicionário
            (múltiplas threads podem ler/escrever simultaneamente)
        _server_socket: socket TCP do servidor
    """

    def __init__(self):
        # Dicionário de Agentes registrados: {agent_id: socket}
        # Protegido por lock porque múltiplas threads acessam
        self._registered_agents: dict[str, socket.socket] = {}

        # Lock (mutex) para acesso thread-safe ao dicionário de Agentes
        # Sem isso, duas threads escrevendo simultaneamente podem
        # corromper o dicionário (race condition)
        self._agents_lock = threading.Lock()

        # Dicionário auxiliar para Service Discovery (Topologia)
        # Mantém mapeamento: {agent_id: ip_address}
        self._agent_ips: dict[str, str] = {}

        # Socket do servidor TCP (será criado em start())
        self._server_socket: socket.socket | None = None

        # Socket UDP para heartbeats (será criado em start())
        self._udp_socket: socket.socket | None = None

        # Dicionário de status de heartbeat: {agent_id: último_timestamp}
        # Usado para rastrear quais Agentes estão vivos
        self._heartbeat_status: dict[str, float] = {}

        # Lock para acesso thread-safe ao dicionário de heartbeats
        self._heartbeat_lock = threading.Lock()

    def start(self):
        """
        Inicia o Broker: cria o socket, faz bind/listen, e entra
        no loop de aceitação de conexões.
        """
        logger.info("=" * 60)
        logger.info("BROKER DE INTELIGÊNCIA DE AMEAÇAS — INICIANDO")
        logger.info("=" * 60)

        # ---- Criar socket TCP/IPv4 do servidor ----
        # AF_INET = IPv4, SOCK_STREAM = TCP
        self._server_socket = socket.socket(
            socket.AF_INET,      # família: IPv4
            socket.SOCK_STREAM,  # tipo: TCP (stream)
        )

        # ---- Configurar SO_REUSEADDR ----
        # Sem esta opção, após fechar o Broker, a porta fica bloqueada
        # por ~60 segundos (estado TIME_WAIT do TCP). Com SO_REUSEADDR,
        # podemos reiniciar o Broker imediatamente.
        # SOL_SOCKET = nível de opção (socket genérico, não específico TCP)
        self._server_socket.setsockopt(
            socket.SOL_SOCKET,     # nível: socket genérico
            socket.SO_REUSEADDR,   # opção: reutilizar endereço
            1,                     # valor: ativado (1 = True)
        )

        # ---- Bind: associar o socket a endereço + porta ----
        # "0.0.0.0" = escutar em TODAS as interfaces de rede
        # (necessário para receber conexões de outras VMs na rede)
        # Retry com delay: quando o ThreatBroker é iniciado como Broker
        # Temporário após uma eleição, a instância anterior pode não ter
        # liberado as portas completamente. Tentamos até 5 vezes.
        max_bind_attempts = 5
        for attempt in range(1, max_bind_attempts + 1):
            try:
                self._server_socket.bind((BROKER_BIND_HOST, BROKER_TCP_PORT))
                break  # bind bem-sucedido
            except OSError as e:
                if attempt < max_bind_attempts:
                    logger.warning(
                        "Bind falhou na tentativa %d/%d: %s. "
                        "Aguardando 2s para a porta ser liberada...",
                        attempt, max_bind_attempts, e,
                    )
                    time.sleep(2)
                else:
                    # Todas as tentativas falharam — propagar o erro
                    logger.error(
                        "Bind falhou após %d tentativas. "
                        "A porta %d não foi liberada.",
                        max_bind_attempts, BROKER_TCP_PORT,
                    )
                    raise

        logger.info(
            "Socket vinculado a %s:%d",  # mensagem
            BROKER_BIND_HOST,             # endereço
            BROKER_TCP_PORT,              # porta
        )

        # ---- Listen: colocar socket em modo passivo (servidor) ----
        # O argumento (backlog=5) define o tamanho da fila de conexões
        # pendentes. Se 5 Agentes tentarem conectar simultaneamente
        # antes do accept(), até 5 ficam na fila; o 6º recebe recusa.
        self._server_socket.listen(5)
        logger.info(
            "Broker escutando na porta %d. "  # mensagem
            "Aguardando conexões de Agentes...",
            BROKER_TCP_PORT,                  # porta
        )

        # ---- Configurar timeout no accept() ----
        # settimeout(1.0) faz o accept() levantar socket.timeout
        # após 1 segundo sem nova conexão. Isso permite verificar
        # o Ctrl+C periodicamente em vez de ficar bloqueado para sempre.
        self._server_socket.settimeout(1.0)

        # ---- Criar e iniciar socket UDP para heartbeats ----
        # Socket separado do TCP, na porta BROKER_UDP_PORT
        self._start_heartbeat_listener()

        # ---- Handler para Ctrl+C (encerramento gracioso) ----
        # Captura o sinal SIGINT para fechar os sockets e encerrar
        def signal_handler(signum, frame):
            logger.info("\nCtrl+C recebido. Encerrando Broker...")
            # Fechar o socket TCP do servidor
            self._server_socket.close()
            # Fechar o socket UDP de heartbeats
            if self._udp_socket:
                self._udp_socket.close()
            # Fechar todas as conexões de Agentes registrados
            self._disconnect_all_agents()
            # Encerrar o programa
            sys.exit(0)

        # Registrar o handler para o sinal SIGINT (Ctrl+C)
        # NOTA: signal.signal() só pode ser chamado na thread principal.
        # Quando o ThreatBroker é instanciado como Broker Temporário
        # dentro de uma thread daemon (após eleição), esta chamada
        # falharia com ValueError. Por isso, verificamos antes.
        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGINT, signal_handler)
        else:
            logger.info(
                "ThreatBroker iniciado em thread secundária — "
                "signal handler de Ctrl+C não registrado (gerenciado pelo Agente)."
            )

        # ---- Loop principal: aceitar novas conexões TCP ----
        # accept() bloqueia até um cliente conectar (ou timeout)
        self._accept_loop()

    def _accept_loop(self):
        """
        Loop infinito que aceita novas conexões TCP de Agentes.

        Para cada nova conexão, cria uma thread dedicada para
        lidar com aquele cliente (padrão "thread per client").

        Este padrão é simples e funcional para poucos clientes
        (nosso caso: dezenas de VMs, não milhares).
        """
        while True:
            try:
                # ---- accept(): esperar nova conexão ----
                # Bloqueia até um Agente conectar (three-way handshake)
                # Retorna:
                #   client_socket: socket da conexão com o cliente
                #   client_address: tupla (IP, porta) do cliente
                client_socket, client_address = self._server_socket.accept()

                # Log da nova conexão
                logger.info(
                    "Nova conexão recebida de %s:%d",  # mensagem
                    client_address[0],                  # IP do cliente
                    client_address[1],                  # porta do cliente
                )

                # ---- Criar thread para lidar com este cliente ----
                # Cada conexão recebe sua própria thread para não
                # bloquear o accept() de novas conexões
                client_thread = threading.Thread(
                    target=self._handle_client,       # função a executar
                    args=(client_socket, client_address),  # argumentos
                    daemon=True,                       # morre com o programa
                    name=f"Client-{client_address[0]}:{client_address[1]}",
                )
                # Iniciar a thread
                client_thread.start()

            except socket.timeout:
                # accept() atingiu o timeout de 1s sem nova conexão
                # Isso é normal — voltar ao loop e verificar Ctrl+C
                continue

            except OSError:
                # Socket foi fechado (provavelmente pelo signal handler)
                logger.info("Socket do servidor fechado. Saindo do accept loop.")
                # Sair do loop
                break

    def _handle_client(
        self,
        client_socket: socket.socket,  # socket da conexão
        client_address: tuple,          # (IP, porta) do cliente
    ):
        """
        Lida com uma conexão TCP individual de um Agente.

        Dois tipos de conexão são tratados:
          1. REGISTRO (persistente): Agente envia {"type": "register"}
             e mantém a conexão aberta para receber broadcasts.
          2. ALERTA (temporária): Agente envia {"type": "alert"}
             e fecha a conexão logo após.

        Args:
            client_socket: socket conectado ao Agente
            client_address: tupla (IP, porta) do Agente
        """
        try:
            # ---- Receber primeira mensagem do Agente ----
            # A primeira mensagem determina o tipo de conexão
            message = receive_message(client_socket)

            # Se a conexão foi fechada antes de enviar dados
            if message is None:
                logger.warning(
                    "Cliente %s:%d desconectou sem enviar dados.",  # aviso
                    client_address[0],   # IP
                    client_address[1],   # porta
                )
                # Fechar o socket e retornar
                client_socket.close()
                return

            # ---- Rotear por tipo de mensagem ----
            # Extrair o tipo da mensagem (register ou alert)
            msg_type = message.get("type", "unknown")

            if msg_type == "register":
                # ---- REGISTRO: conexão persistente ----
                self._handle_register(client_socket, client_address, message)

            elif msg_type == "alert":
                # ---- ALERTA: conexão temporária ----
                self._handle_alert(client_socket, client_address, message)

            else:
                # Tipo desconhecido — logar e fechar
                logger.warning(
                    "Tipo de mensagem desconhecido '%s' de %s:%d",  # aviso
                    msg_type,              # tipo recebido
                    client_address[0],     # IP
                    client_address[1],     # porta
                )
                # Fechar o socket
                client_socket.close()

        except Exception as e:
            # Erro inesperado ao processar o cliente
            logger.error(
                "Erro ao processar cliente %s:%d: %s",  # mensagem
                client_address[0],                       # IP
                client_address[1],                       # porta
                e,                                       # detalhes do erro
            )
            # Garantir que o socket é fechado
            client_socket.close()

    def _handle_register(
        self,
        client_socket: socket.socket,  # socket da conexão persistente
        client_address: tuple,          # (IP, porta) do Agente
        message: dict,                  # mensagem de registro recebida
    ):
        """
        Processa um registro de Agente.

        1. Extrai o agent_id da mensagem
        2. Armazena o socket na lista de Agentes registrados (com lock)
        3. Mantém a conexão aberta (o socket fica armazenado)

        O socket armazenado será usado por _broadcast() para enviar
        alertas futuros para este Agente.

        Args:
            client_socket: socket TCP conectado ao Agente
            client_address: tupla (IP, porta)
            message: dicionário com dados do registro
        """
        # Extrair o identificador do Agente
        agent_id = message.get("agent_id", f"unknown-{client_address[0]}")

        # ---- Seção crítica: acesso ao dicionário compartilhado ----
        # Usamos 'with self._agents_lock' (context manager) que:
        #   1. Adquire o lock antes de entrar no bloco
        #   2. Libera o lock automaticamente ao sair (mesmo com exceção)
        # Isso garante que apenas uma thread modifica o dicionário por vez
        with self._agents_lock:
            # Verificar se já existe um Agente com esse ID
            if agent_id in self._registered_agents:
                # Fechar a conexão antiga antes de substituir
                logger.warning(
                    "Agente '%s' já estava registrado. "  # aviso
                    "Substituindo conexão antiga.",        # ação
                    agent_id,                              # ID do Agente
                )
                # Fechar socket antigo de forma segura
                try:
                    self._registered_agents[agent_id].close()
                except OSError:
                    # Se o socket antigo já estava fechado, ignorar
                    pass

            # Armazenar o novo socket associado ao agent_id
            self._registered_agents[agent_id] = client_socket
            # Armazenar o IP associado ao agent_id para Service Discovery
            self._agent_ips[agent_id] = client_address[0]

        # Log do registro bem-sucedido
        logger.info(
            "Agente registrado: id='%s', endereço=%s:%d",  # mensagem
            agent_id,              # ID do Agente
            client_address[0],     # IP
            client_address[1],     # porta
        )

        # Logar quantidade total de Agentes conectados
        with self._agents_lock:
            total = len(self._registered_agents)
        logger.info("Total de Agentes registrados: %d", total)

        # NOTA: NÃO fechamos o socket aqui!
        # O socket fica armazenado em _registered_agents para
        # ser usado por _broadcast() quando houver alertas.

        # SERVICE DISCOVERY:
        # Fazer broadcast da nova topologia da rede para todos
        # os Agentes conectados, incluindo o novo que acabou de entrar.
        self._broadcast_peer_list()

    def _broadcast_peer_list(self):
        """
        Gera uma lista atualizada de todos os Agentes conectados e
        envia para toda a rede (Service Discovery).
        """
        with self._agents_lock:
            # Converter dicionário para lista de tuplas [(id, ip), ...]
            peers_list = list(self._agent_ips.items())
        
        # Montar mensagem de atualização de topologia
        message = {
            "type": "peer_update",
            "peers": peers_list,
        }

        logger.info(
            "Service Discovery: Fazendo broadcast da nova topologia "
            "(%d peers na rede)", len(peers_list),
        )
        # Retransmitir a lista (sem excluir ninguém, todos precisam saber)
        # Usamos is_topology_update=True para evitar loop infinito de
        # falhas caso algum socket caia durante este envio.
        self._broadcast(message, is_topology_update=True)

    def _handle_alert(
        self,
        client_socket: socket.socket,  # socket da conexão temporária
        client_address: tuple,          # (IP, porta) do Agente que enviou
        message: dict,                  # mensagem de alerta
    ):
        """
        Processa um alerta de ameaça recebido de um Agente.

        1. Loga o alerta recebido
        2. Fecha a conexão temporária (padrão short-lived)
        3. Faz BROADCAST do alerta para todos os OUTROS Agentes registrados

        O broadcast é o coração do modelo Pub/Sub:
          - O Agente que detectou o ataque PUBLICA o alerta
          - O Broker RETRANSMITE para todos os ASSINANTES (outros Agentes)
          - Cada Agente receptor decide o que fazer (bloquear ou não)

        Args:
            client_socket: socket TCP (será fechado após processar)
            client_address: tupla (IP, porta)
            message: dicionário com dados do alerta
        """
        # Extrair dados do alerta
        agent_id = message.get("agent_id", "unknown")  # quem enviou
        action = message.get("action", "unknown")       # ban ou unban
        ip = message.get("ip", "unknown")               # IP ameaçador

        # Log do alerta recebido
        logger.info(
            "ALERTA recebido do Agente '%s': "  # quem enviou
            "action=%s, ip=%s",                  # detalhes da ameaça
            agent_id,                            # ID do Agente
            action,                              # tipo de ação
            ip,                                  # IP do atacante
        )

        # ---- Fechar a conexão temporária ----
        # O Agente enviou o alerta por uma conexão short-lived,
        # que não precisa mais ficar aberta
        client_socket.close()

        # ---- Fazer broadcast para os OUTROS Agentes ----
        # O alerta é repassado para todos, EXCETO o Agente que enviou
        # (ele já bloqueou o IP localmente)
        self._broadcast(message, exclude_agent_id=agent_id)

    def _broadcast(
        self,
        message: dict,              # mensagem a ser retransmitida
        exclude_agent_id: str = "",  # Agente a excluir do broadcast
        is_topology_update: bool = False, # Evita recursão se houver falhas
    ):
        """
        Retransmite uma mensagem para todos os Agentes registrados,
        exceto o que enviou o alerta original.

        Este é o mecanismo central do Publish/Subscribe:
          - Itera sobre todos os sockets armazenados
          - Para cada um, tenta enviar a mensagem via protocolo TCP
          - Se falhar (socket morto), remove o Agente da lista

        Args:
            message: dicionário com a mensagem a retransmitir
            exclude_agent_id: ID do Agente que NÃO deve receber
                             (evita eco — o originador já processou)
        """
        # Lista de Agentes que falharam (sockets mortos)
        # Não podemos remover do dicionário enquanto iteramos sobre ele,
        # então coletamos os IDs e removemos depois
        failed_agents = []

        # ---- Seção crítica: iterar sobre o dicionário ----
        with self._agents_lock:
            # Iterar sobre uma cópia dos items (.items()) para segurança
            for agent_id, agent_socket in self._registered_agents.items():

                # Pular o Agente que enviou o alerta (evitar eco)
                if agent_id == exclude_agent_id:
                    continue

                try:
                    # Tentar enviar a mensagem pelo protocolo length-prefix
                    send_message(agent_socket, message)

                    # Log de sucesso para cada Agente
                    logger.info(
                        "Broadcast enviado para Agente '%s'",  # mensagem
                        agent_id,                               # destinatário
                    )

                except (BrokenPipeError, ConnectionResetError, OSError) as e:
                    # Socket morto — o Agente desconectou sem avisar
                    logger.warning(
                        "Falha ao enviar broadcast para Agente '%s': %s. "
                        "Removendo da lista.",  # mensagem
                        agent_id,               # Agente que falhou
                        e,                      # detalhes do erro
                    )
                    # Marcar para remoção posterior
                    failed_agents.append(agent_id)

        # ---- Remover Agentes que falharam ----
        # Feito fora da iteração para evitar 'dictionary changed size'
        if failed_agents:
            with self._agents_lock:
                for agent_id in failed_agents:
                    # Tentar fechar o socket de forma segura
                    try:
                        self._registered_agents[agent_id].close()
                    except OSError:
                        pass  # Socket já estava fechado, ignorar
                    # Remover do dicionário de sockets e IPs
                    del self._registered_agents[agent_id]
                    self._agent_ips.pop(agent_id, None)
                    logger.info("Agente '%s' removido da lista.", agent_id)

        # Log do resultado do broadcast
        with self._agents_lock:
            remaining = len(self._registered_agents)
        logger.info(
            "Broadcast concluído. Agentes ativos: %d",  # resumo
            remaining,                                    # total restante
        )

        # Se removemos agentes e esta chamada não era de Service Discovery,
        # significa que a topologia mudou silenciosamente. Disparamos
        # uma atualização para a rede.
        if failed_agents and not is_topology_update:
            self._broadcast_peer_list()

    def _disconnect_all_agents(self):
        """
        Fecha todas as conexões de Agentes registrados.
        Chamada durante o encerramento gracioso do Broker.
        """
        # Seção crítica: acessar o dicionário compartilhado
        with self._agents_lock:
            # Iterar sobre todos os Agentes
            for agent_id, agent_socket in self._registered_agents.items():
                try:
                    # Fechar cada socket
                    agent_socket.close()
                    logger.info(
                        "Conexão com Agente '%s' fechada.",  # mensagem
                        agent_id,                            # ID
                    )
                except OSError:
                    # Socket já estava fechado
                    pass

            # Limpar o dicionário
            self._registered_agents.clear()

        # Log final
        logger.info("Todas as conexões de Agentes foram fechadas.")


    def _start_heartbeat_listener(self):
        """
        Cria e inicia a thread de escuta UDP para heartbeats.

        O socket UDP é diferente do TCP:
          - SOCK_DGRAM em vez de SOCK_STREAM
          - Não precisa de listen() nem accept() — UDP não tem conexão
          - Usa recvfrom() para receber pacotes e saber quem enviou
          - bind() para escutar em uma porta específica
        """
        # ---- Criar socket UDP ----
        # AF_INET = IPv4, SOCK_DGRAM = UDP (datagram, sem conexão)
        self._udp_socket = socket.socket(
            socket.AF_INET,     # família: IPv4
            socket.SOCK_DGRAM,  # tipo: UDP (datagrama)
        )

        # ---- Configurar SO_REUSEADDR (igual ao TCP) ----
        # Permite reutilizar a porta imediatamente após reiniciar
        self._udp_socket.setsockopt(
            socket.SOL_SOCKET,     # nível: socket genérico
            socket.SO_REUSEADDR,   # opção: reutilizar endereço
            1,                     # valor: ativado
        )

        # ---- Bind: associar a porta UDP ----
        # Diferente de TCP, NÃO chamamos listen() depois — UDP é stateless
        self._udp_socket.bind((BROKER_BIND_HOST, BROKER_UDP_PORT))
        logger.info(
            "Socket UDP vinculado a %s:%d para heartbeats",  # mensagem
            BROKER_BIND_HOST,  # endereço
            BROKER_UDP_PORT,   # porta
        )

        # ---- Iniciar thread de escuta UDP ----
        # Thread dedicada para não bloquear o accept loop TCP
        heartbeat_thread = threading.Thread(
            target=self._heartbeat_listener,  # função a executar
            daemon=True,                       # morre com o programa
            name="HeartbeatListenerThread",    # nome para logs
        )
        # Iniciar a thread
        heartbeat_thread.start()
        logger.info("Thread HeartbeatListener iniciada na porta UDP %d", BROKER_UDP_PORT)

    def _heartbeat_listener(self):
        """
        Loop de escuta de pacotes UDP de heartbeat dos Agentes.

        Para cada pacote recebido:
          1. Decodifica o JSON
          2. Extrai o agent_id e timestamp
          3. Atualiza o dicionário de status de heartbeat
          4. Verifica e loga Agentes inativos

        UDP com recvfrom():
          - recvfrom(buffer_size) retorna (dados, endereço_remetente)
          - Diferente de TCP: recebe de QUALQUER remetente sem
            conexão prévia (stateless)
          - buffer_size=1024 é suficiente para nossos JSONs pequenos
        """
        logger.info("Thread HeartbeatListener: escutando heartbeats UDP...")

        # Configurar timeout para permitir verificação periódica
        # de Agentes inativos e shutdown gracioso
        try:
            self._udp_socket.settimeout(5.0)
        except OSError:
            # Socket pode ter sido fechado externamente (ex: demoção)
            logger.info("Socket UDP já fechado antes de iniciar HeartbeatListener.")
            return

        while True:
            try:
                # ---- recvfrom(): receber pacote UDP ----
                # Retorna tupla (dados_em_bytes, (ip_remetente, porta_remetente))
                # Bloqueia até receber um pacote ou atingir o timeout
                data, addr = self._udp_socket.recvfrom(1024)

                # Decodificar bytes → string JSON → dicionário Python
                heartbeat = json.loads(data.decode("utf-8"))

                # Extrair dados do heartbeat
                agent_id = heartbeat.get("agent_id", "unknown")  # quem enviou
                seq = heartbeat.get("seq", 0)                     # sequência
                status = heartbeat.get("status", "unknown")       # status

                # ---- Atualizar timestamp do último heartbeat ----
                # Seção crítica: acesso ao dicionário compartilhado
                with self._heartbeat_lock:
                    self._heartbeat_status[agent_id] = time.time()

                # Log do heartbeat recebido (DEBUG para não poluir)
                logger.debug(
                    "Heartbeat recebido: agent_id='%s', seq=%d, "
                    "status='%s', de %s:%d",   # mensagem
                    agent_id,                    # ID do Agente
                    seq,                         # número de sequência
                    status,                      # status reportado
                    addr[0],                     # IP do remetente
                    addr[1],                     # porta do remetente
                )

            except socket.timeout:
                # Timeout de 5s sem receber pacote — verificar inativos
                self._check_inactive_agents()

            except json.JSONDecodeError as e:
                # Pacote com JSON malformado — ignorar
                logger.warning(
                    "Heartbeat com JSON inválido recebido: %s",  # aviso
                    e,                                            # detalhes
                )

            except OSError:
                # Socket fechado (shutdown do Broker)
                logger.info("Socket UDP fechado. Encerrando HeartbeatListener.")
                break

    def _check_inactive_agents(self):
        """
        Verifica quais Agentes estão inativos (sem heartbeat recente).

        Para cada Agente no dicionário de heartbeats, calcula o tempo
        desde o último heartbeat. Se ultrapassar HEARTBEAT_TIMEOUT,
        o Agente é considerado MORTO. Seu socket é fechado, ele é
        removido dos registros, e a nova topologia é enviada à rede.
        """
        now = time.time()
        dead_agents = []

        # Seção crítica: acessar o dicionário de heartbeats
        with self._heartbeat_lock:
            for agent_id, last_heartbeat in list(self._heartbeat_status.items()):
                elapsed = now - last_heartbeat
                if elapsed > HEARTBEAT_TIMEOUT:
                    dead_agents.append(agent_id)
                    # Remover do rastreamento de heartbeats
                    del self._heartbeat_status[agent_id]

        if dead_agents:
            # Remover os Agentes mortos do registro TCP
            with self._agents_lock:
                for agent_id in dead_agents:
                    logger.warning(
                        "ALERTA: Agente '%s' sem heartbeat (timeout: %ds). "
                        "Removendo da rede e fechando conexão TCP.",
                        agent_id, HEARTBEAT_TIMEOUT,
                    )
                    # Fechar socket
                    sock = self._registered_agents.get(agent_id)
                    if sock:
                        try:
                            sock.close()
                        except OSError:
                            pass
                    # Limpar dicionários
                    self._registered_agents.pop(agent_id, None)
                    self._agent_ips.pop(agent_id, None)

            # Notificar os sobreviventes sobre a mudança na topologia
            self._broadcast_peer_list()


# ============================================================
# Ponto de entrada do Broker
# ============================================================
if __name__ == "__main__":
    # Criar instância do Broker
    broker = ThreatBroker()
    # Iniciar o servidor (bloqueia no accept loop TCP)
    broker.start()
