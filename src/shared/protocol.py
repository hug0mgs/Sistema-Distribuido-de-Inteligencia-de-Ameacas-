"""
protocol.py — Protocolo de Mensagens TCP (Length-Prefixed JSON)

PROBLEMA que este módulo resolve:
    TCP é um protocolo de STREAM (fluxo contínuo de bytes), não de
    mensagens. Se enviarmos dois JSONs seguidos pelo socket, o receptor
    pode receber tudo junto, ou receber metade de um JSON em uma
    leitura e a outra metade na próxima. Isso chama-se "TCP framing
    problem" (problema de enquadramento TCP).

SOLUÇÃO — Length-Prefix Protocol:
    Antes de cada mensagem JSON, enviamos um HEADER de 4 bytes contendo
    o tamanho exato (em bytes) da mensagem que virá em seguida.

    Formato do pacote na rede:
    ┌──────────────┬───────────────────────────┐
    │ 4 bytes      │ N bytes                   │
    │ (tamanho N)  │ (mensagem JSON em UTF-8)  │
    └──────────────┴───────────────────────────┘

    O receptor primeiro lê exatamente 4 bytes, decodifica o tamanho N,
    e então lê exatamente N bytes — garantindo que recebe uma mensagem
    completa, nem mais, nem menos.

BIBLIOTECA struct:
    A biblioteca 'struct' do Python converte dados Python em bytes no
    formato binário da linguagem C. Usamos o formato '>I' que significa:
      '>' = big-endian (byte mais significativo primeiro — padrão de rede)
      'I' = unsigned int de 4 bytes (suporta mensagens de até ~4GB)

Uso:
    # Enviar uma mensagem
    send_message(socket, {"action": "ban", "ip": "1.2.3.4"})

    # Receber uma mensagem
    data = receive_message(socket)
"""

# struct: converte entre Python e representação binária em C
# Necessário para empacotar/desempacotar o header de 4 bytes
import struct

# json: serializa dicionários Python em strings JSON e vice-versa
# Formato escolhido por ser legível e fácil de depurar
import json

# socket: tipos do módulo socket, usado para type hints
import socket

# logging: registro estruturado de eventos do protocolo
import logging

# Logger específico deste módulo
logger = logging.getLogger(__name__)

# ============================================================
# Constante do Header
# ============================================================
# '>I' = formato struct para unsigned int 32-bit big-endian
# struct.calcsize('>I') retorna 4 — tamanho do header em bytes
HEADER_FORMAT = ">I"

# Tamanho fixo do header: sempre 4 bytes
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)


def send_message(sock: socket.socket, data: dict) -> None:
    """
    Envia uma mensagem (dicionário) pelo socket TCP usando
    o protocolo length-prefix.

    Passos:
      1. Serializa o dicionário em JSON (string)
      2. Codifica o JSON em bytes UTF-8
      3. Calcula o tamanho dos bytes
      4. Empacota o tamanho em 4 bytes (header)
      5. Envia header + corpo pelo socket com sendall()

    Args:
        sock: socket TCP já conectado.
        data: dicionário Python a ser enviado.

    Raises:
        BrokenPipeError: se a conexão foi fechada pelo outro lado.
        OSError: se houver outro erro de rede.

    Nota sobre sendall() vs send():
        - send() pode enviar MENOS bytes que o pedido (envio parcial)
        - sendall() garante que TODOS os bytes são enviados, fazendo
          múltiplas chamadas a send() internamente se necessário
    """
    # Passo 1: dicionário Python → string JSON
    json_string = json.dumps(data)

    # Passo 2: string JSON → bytes codificados em UTF-8
    message_bytes = json_string.encode("utf-8")

    # Passo 3: calcular o tamanho da mensagem em bytes
    message_length = len(message_bytes)

    # Passo 4: empacotar o tamanho em 4 bytes big-endian
    # Exemplo: tamanho 256 → b'\x00\x00\x01\x00'
    header = struct.pack(HEADER_FORMAT, message_length)

    # Passo 5: enviar header (4 bytes) + corpo (N bytes)
    # sendall() garante envio completo de ambos os pedaços
    sock.sendall(header + message_bytes)

    # Log para depuração (nível DEBUG para não poluir em produção)
    logger.debug(
        "Mensagem enviada (%d bytes): %s",  # formato do log
        message_length,                      # tamanho da mensagem
        json_string,                         # conteúdo JSON (para debug)
    )


def receive_message(sock: socket.socket) -> dict | None:
    """
    Recebe uma mensagem completa do socket TCP usando o protocolo
    length-prefix.

    Passos:
      1. Lê exatamente 4 bytes (header com o tamanho)
      2. Desempacota o header para obter o tamanho N
      3. Lê exatamente N bytes (corpo da mensagem)
      4. Decodifica UTF-8 → string JSON
      5. Desserializa JSON → dicionário Python

    Args:
        sock: socket TCP já conectado.

    Returns:
        Dicionário Python com os dados da mensagem, ou None se a
        conexão foi fechada (o outro lado desconectou).

    A função _recv_exact() é usada para garantir que lemos o número
    exato de bytes, mesmo que o SO entregue os dados em pedaços menores.
    """
    # Passo 1: ler exatamente 4 bytes do header
    header_bytes = _recv_exact(sock, HEADER_SIZE)

    # Se recebemos None ou bytes vazios, a conexão foi fechada
    if header_bytes is None:
        # Retorna None para sinalizar desconexão ao chamador
        return None

    # Passo 2: desempacotar os 4 bytes para obter o tamanho da mensagem
    # struct.unpack retorna uma tupla, pegamos o primeiro (e único) elemento
    (message_length,) = struct.unpack(HEADER_FORMAT, header_bytes)

    # Passo 3: ler exatamente N bytes do corpo da mensagem
    message_bytes = _recv_exact(sock, message_length)

    # Se recebemos None, a conexão caiu no meio da mensagem
    if message_bytes is None:
        # Mensagem incompleta — conexão perdida
        logger.warning("Conexão perdida no meio de uma mensagem.")
        return None

    # Passo 4: decodificar bytes → string JSON
    json_string = message_bytes.decode("utf-8")

    # Passo 5: desserializar string JSON → dicionário Python
    data = json.loads(json_string)

    # Log para depuração
    logger.debug(
        "Mensagem recebida (%d bytes): %s",  # formato do log
        message_length,                       # tamanho da mensagem
        json_string,                          # conteúdo JSON (para debug)
    )

    # Retornar o dicionário com os dados da mensagem
    return data


def _recv_exact(sock: socket.socket, num_bytes: int) -> bytes | None:
    """
    Lê EXATAMENTE num_bytes do socket, mesmo que o SO entregue
    os dados em pedaços menores.

    PROBLEMA que esta função resolve:
        socket.recv(1024) NÃO garante que receberá 1024 bytes.
        O SO pode entregar 500 bytes agora e 524 depois (fragmentação).
        Para o protocolo length-prefix funcionar, precisamos ler o
        número EXATO de bytes — nem mais, nem menos.

    SOLUÇÃO:
        Loop que acumula bytes em um buffer até atingir a quantidade
        desejada. Cada chamada a recv() pode retornar de 1 a num_bytes
        de cada vez.

    Args:
        sock: socket TCP conectado.
        num_bytes: quantidade exata de bytes a receber.

    Returns:
        bytes com exatamente num_bytes, ou None se a conexão fechou.
    """
    # Buffer que acumula os bytes recebidos
    buffer = b""

    # Loop até acumularmos a quantidade exata de bytes
    while len(buffer) < num_bytes:
        # Calcular quantos bytes ainda faltam
        remaining = num_bytes - len(buffer)

        # recv() retorna até 'remaining' bytes (pode ser menos)
        chunk = sock.recv(remaining)

        # Se recv() retorna bytes vazios (b""), significa que
        # o outro lado fechou a conexão (EOF)
        if not chunk:
            # Retorna None para sinalizar desconexão
            return None

        # Acumular o pedaço recebido no buffer
        buffer += chunk

    # Retornar o buffer completo com exatamente num_bytes
    return buffer
