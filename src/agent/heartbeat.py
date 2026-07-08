"""
heartbeat.py — Thread de Heartbeat UDP (Pulso de Vida)

CONCEITO — Heartbeat (Batimento Cardíaco):
    Em sistemas distribuídos, precisamos saber se os nós estão vivos.
    O Heartbeat é um pacote periódico que cada Agente envia ao Broker
    dizendo "estou aqui, estou vivo". Se o Broker parar de receber
    heartbeats de um Agente, pode assumir que ele caiu.

POR QUE UDP E NÃO TCP?
    - TCP exige conexão (three-way handshake) e garantia de entrega.
      Para um simples pulso de vida, isso é OVERHEAD desnecessário.
    - UDP é "fire and forget" (dispara e esquece): envia o pacote e
      não espera confirmação. Se um heartbeat se perder, não é grave
      — o próximo chegará em poucos segundos.
    - UDP é mais LEVE: sem conexão, sem retransmissão, sem ordenação.
      Ideal para monitoramento de disponibilidade.

PROTOCOLO UDP vs TCP:
    ┌──────────────┬──────────────────┬──────────────────┐
    │ Aspecto      │ TCP              │ UDP              │
    ├──────────────┼──────────────────┼──────────────────┤
    │ Conexão      │ Sim (handshake)  │ Não (stateless)  │
    │ Garantia     │ Entrega ordenada │ Nenhuma           │
    │ Overhead     │ Alto             │ Baixo            │
    │ Uso aqui     │ Alertas (ban)    │ Heartbeat        │
    └──────────────┴──────────────────┴──────────────────┘

    Alertas de ban PRECISAM de TCP porque perder uma regra de firewall
    é inaceitável. Heartbeats podem usar UDP porque perder um pulso
    esporádico é tolerável.

SOCKET UDP:
    socket.socket(AF_INET, SOCK_DGRAM)
      - AF_INET = IPv4
      - SOCK_DGRAM = Datagram (UDP) — cada sendto() envia um pacote
        independente, sem conexão prévia.
    sendto(data, (host, port)) — envia pacote para o destino
    (diferente de TCP que usa connect() + send())
"""

# socket: API de rede — aqui usamos SOCK_DGRAM para UDP
import socket

# threading: thread daemon para envio periódico
import threading

# time: timestamps para o conteúdo do heartbeat
import time

# json: serialização do payload do heartbeat
import json

# logging: registro de eventos
import logging

# Configurações do Agente
from agent import config

# Logger específico deste módulo
logger = logging.getLogger(__name__)


class HeartbeatSender(threading.Thread):
    """
    Thread que envia pacotes Heartbeat UDP periodicamente ao Broker.

    A cada HEARTBEAT_INTERVAL segundos, envia um pacote UDP contendo:
      - agent_id: identificador deste Agente
      - timestamp: momento do envio (para o Broker calcular latência)
      - status: "alive" (indicando que o Agente está operacional)

    Como é UDP (SOCK_DGRAM), NÃO há conexão prévia. Cada sendto()
    é independente — se um pacote se perder, o próximo será enviado
    em poucos segundos.

    Atributos:
        broker_host: IP do Broker para envio dos heartbeats
        broker_port: porta UDP do Broker
        agent_id: identificador deste Agente
        _stop_event: sinaliza encerramento da thread
    """

    def __init__(
        self,
        broker_host: str,  # IP do Broker (ex: "192.168.1.10")
        broker_port: int,  # porta UDP do Broker (ex: 5601)
        agent_id: str,     # identificador do Agente (ex: "agent-01")
    ):
        # daemon=True: morre automaticamente com o programa principal
        # name: nome legível para logs
        super().__init__(daemon=True, name="HeartbeatSenderThread")

        # Armazenar parâmetros como atributos
        self.broker_host = broker_host  # destino dos heartbeats
        self.broker_port = broker_port  # porta UDP do Broker
        self.agent_id = agent_id        # nosso identificador

        # Lock para acesso thread-safe ao broker_host e broker_port.
        # Necessário porque o ElectionManager pode chamar update_broker()
        # de outra thread durante uma eleição ou failback.
        self._broker_lock = threading.Lock()

        # Evento de parada para encerramento gracioso
        self._stop_event = threading.Event()

    def stop(self):
        """Sinaliza para a thread encerrar na próxima iteração."""
        logger.info("Sinalizando parada da thread HeartbeatSender...")
        # Marcar o evento de parada
        self._stop_event.set()

    def update_broker(self, new_host: str, new_port: int):
        """
        Atualiza o destino dos heartbeats para um novo Broker.

        Chamado pelo main.py quando:
          - Um novo Broker Temporário é eleito (eleição)
          - O Broker original volta (failback / demotion)

        Thread-safe: usa lock para proteger a atualização.

        Args:
            new_host: novo IP do Broker.
            new_port: nova porta UDP do Broker.
        """
        with self._broker_lock:
            old_host = self.broker_host
            self.broker_host = new_host
            self.broker_port = new_port

        logger.info(
            "HeartbeatSender: destino atualizado de %s para %s:%d",
            old_host, new_host, new_port,
        )

    def run(self):
        """
        Loop principal da thread HeartbeatSender.

        1. Cria um socket UDP (SOCK_DGRAM)
        2. Entra em loop enviando heartbeats a cada N segundos
        3. Cada heartbeat é um pacote JSON com ID, timestamp e status

        Diferente de TCP:
          - NÃO chamamos connect() — UDP não tem conexão
          - Usamos sendto() em vez de send() — especificamos o destino
            em cada envio (cada pacote pode ir para um destino diferente)
        """
        logger.info(
            "Thread HeartbeatSender iniciada. "     # mensagem
            "Destino: %s:%d, Intervalo: %ds",       # detalhes
            self.broker_host,                        # IP destino
            self.broker_port,                        # porta destino
            config.HEARTBEAT_INTERVAL,               # intervalo
        )

        # ---- Criar socket UDP ----
        # AF_INET = IPv4
        # SOCK_DGRAM = Datagram = UDP (cada envio é um pacote independente)
        # 'with' garante fechamento automático ao sair
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:

            # Contador de heartbeats enviados (para sequência nos logs)
            heartbeat_count = 0

            # ---- Loop de envio periódico ----
            while not self._stop_event.is_set():

                # Incrementar contador de sequência
                heartbeat_count += 1

                # ---- Montar payload do heartbeat ----
                # JSON com informações de status do Agente
                heartbeat_data = {
                    "type": "heartbeat",             # tipo da mensagem
                    "agent_id": self.agent_id,       # quem está enviando
                    "timestamp": time.time(),         # momento do envio
                    "status": "alive",                # status do Agente
                    "seq": heartbeat_count,           # número de sequência
                }

                # Serializar para JSON e codificar em bytes UTF-8
                payload = json.dumps(heartbeat_data).encode("utf-8")

                try:
                    # ---- Ler destino atual (thread-safe) ----
                    # O destino pode mudar dinamicamente se houver
                    # uma eleição ou failback. Lemos sob lock.
                    with self._broker_lock:
                        current_host = self.broker_host
                        current_port = self.broker_port

                    # ---- Enviar pacote UDP via sendto() ----
                    # sendto() é específico de UDP:
                    #   - Primeiro argumento: bytes a enviar
                    #   - Segundo argumento: tupla (host, port) do destino
                    # Não precisa de connect() — cada sendto() é independente
                    udp_socket.sendto(
                        payload,                                   # dados a enviar
                        (current_host, current_port),              # destino (IP, porta)
                    )

                    # Log do heartbeat enviado (nível DEBUG para não poluir)
                    logger.debug(
                        "Heartbeat #%d enviado para %s:%d",  # mensagem
                        heartbeat_count,                      # sequência
                        current_host,                         # IP destino
                        current_port,                         # porta destino
                    )

                except OSError as e:
                    # Erro de rede ao enviar heartbeat
                    # Em UDP, erros são raros (já que não há conexão),
                    # mas podem ocorrer se a rede estiver completamente fora
                    logger.warning(
                        "Falha ao enviar heartbeat #%d: %s",  # mensagem
                        heartbeat_count,                       # sequência
                        e,                                     # erro
                    )

                # ---- Esperar intervalo antes do próximo heartbeat ----
                # Usamos _stop_event.wait() em vez de time.sleep():
                # - time.sleep(10) bloqueia 10s INCONDICIONALMENTE
                # - _stop_event.wait(10) retorna IMEDIATAMENTE se stop()
                #   for chamado, permitindo encerramento rápido
                self._stop_event.wait(config.HEARTBEAT_INTERVAL)

        # Log de encerramento
        logger.info(
            "Thread HeartbeatSender encerrada. "    # mensagem
            "Total de heartbeats enviados: %d",     # resumo
            heartbeat_count,                         # total
        )
