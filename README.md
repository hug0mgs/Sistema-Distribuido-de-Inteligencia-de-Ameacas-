# Sistema Distribuído de Inteligência de Ameaças

## 🛡️ O que é o Sistema?

Este projeto é um **Sistema Distribuído de Inteligência de Ameaças**, inspirado na ferramenta *Fail2Ban*. Ele foi desenvolvido como um trabalho acadêmico de Sistemas de Informação, projetado com qualidade profissional para rodar em ambientes Linux (Debian/Ubuntu).

O objetivo principal do sistema é proteger uma rede de servidores contra ataques de força bruta (focando inicialmente em SSH). Quando um servidor detecta um ataque, ele não apenas se protege bloqueando o atacante localmente, mas também **compartilha essa inteligência** com toda a rede. Assim, se um IP malicioso atacar o "Servidor A", ele será automaticamente bloqueado nos servidores "B", "C" e "D", antes mesmo de tentar atacá-los.

## ⚙️ Como Funciona?

A arquitetura segue o modelo **Publish/Subscribe (Pub/Sub)**, desenhada para ser tolerante a falhas, leve e baseada em eventos. O ecossistema é dividido em duas partes principais: **Agentes** e **Broker**.

### 1. O Broker (Servidor de Coordenação)
O Broker é o nó central da rede. Sua única responsabilidade é **retransmitir mensagens**. Ele não processa logs, não acessa o firewall e não toma decisões de bloqueio. 
- Mantém conexões TCP ativas com todos os Agentes registrados.
- Quando recebe um "Alerta de Ban" de um Agente (Publisher), faz o broadcast (Subscribe) para todos os outros Agentes conectados.
- Monitora a saúde da rede escutando "Pulsos de Vida" (Heartbeats) enviados pelos Agentes.

### 2. O Agente (Nó Distribuído)
O Agente roda em cada servidor que precisa ser protegido. Ele é altamente paralelo, dividido em 5 *Threads* principais:
- **LogMonitor (Detecção):** Fica lendo continuamente o arquivo `/var/log/auth.log` (técnica *tail -f*). Ao detectar 5 falhas de SSH do mesmo IP em 10 minutos, dispara um alerta de bloqueio.
- **NetworkListener (Comunicação TCP):** Mantém uma conexão persistente com o Broker para receber alertas de ataques detectados por outros servidores da rede. Se o Broker ficar inacessível por mais de 30 segundos, aciona a eleição de novo líder.
- **HeartbeatSender (Monitoramento UDP):** Envia pacotes leves (UDP) a cada 10 segundos para avisar ao Broker que o servidor está online.
- **BanManager (Firewall & NTP):** Executa os comandos reais do `iptables` para bloquear pacotes de rede do atacante. Ele também agenda o desbloqueio automático (auto-unban).
- **ElectionManager (Eleição de Líder):** Escuta mensagens UDP de eleição na porta 5602. Quando o Broker cai, coordena uma eleição via **Bully Algorithm** (Garcia-Molina, 1982). O Agente com maior ID é eleito **Broker Temporário** e assume a função de retransmitir mensagens até que o Broker original volte (Failback).

### 📡 Protocolos de Rede e Sistemas Distribuídos Utilizados

Para fins didáticos e técnicos, o sistema implementa protocolos de rede "na unha" (raw sockets):
* **TCP com Length-Prefix Framing:** Usado para envio de Alertas. Resolve o problema de fragmentação do TCP enviando 4 bytes de cabeçalho indicando o tamanho exato da mensagem JSON a ser lida.
* **UDP (Fire and Forget):** Usado para os Heartbeats. Sendo rápido e sem conexão, é ideal para enviar avisos periódicos de "estou vivo" sem sobrecarregar a rede.
* **NTP (Network Time Protocol):** Em sistemas distribuídos, relógios locais dessincronizados causam problemas graves. O sistema consulta servidores globais (pool.ntp.org) para calcular o momento exato em que um IP deve ser desbloqueado. Isso garante que todos os servidores da rede desbloqueiem o atacante exatamente no mesmo segundo.
* **UDP P2P (Eleição de Líder):** Quando o Broker cai, os Agentes se comunicam diretamente via UDP na porta 5602 para eleger um novo líder usando o **Bully Algorithm** (Garcia-Molina, 1982). O protocolo usa 4 tipos de mensagens: `ELECTION` (iniciar eleição), `OK` ("eu tenho prioridade maior"), `COORDINATOR` ("eu sou o novo Broker") e `DEMOTION` ("o Broker original voltou").

### 🔄 Tolerância a Falhas: Eleição de Líder com Broker Temporário

O sistema implementa tolerância a falhas para o centrão da rede (Broker) através de um mecanismo de **Failover com Failback automático**:

1. **Detecção de Falha:** Se o Broker ficar inacessível por mais de 30 segundos, os Agentes o consideram "morto".
2. **Eleição (Bully Algorithm):** Os Agentes se comunicam via UDP P2P. O Agente com o **maior ID** (ordem lexicográfica) vence a eleição.
3. **Broker Temporário:** O vencedor inicia um `ThreatBroker` interno e acumula funções: continua como Agente + roda o Broker.
4. **Recovery Probe:** O Broker Temporário tenta reconectar ao Broker original a cada 30 segundos (máx. 10 minutos).
5. **Failback:** Se o Broker original voltar, o temporário envia `DEMOTION` e todos reconectam ao original.

---

## 🚀 Como Utilizar (Guia de Execução)

### Pré-requisitos
* Máquinas Virtuais (ou instâncias locais/cloud) rodando **Linux (Debian ou Ubuntu)**.
* Serviço **SSH** rodando nas máquinas dos Agentes (`sudo apt install openssh-server`).
* **iptables** instalado (`sudo apt install iptables`).
* Serviço de Logs Open-Source do Linux rodando nas máquinas dos Agentes (`sudo apt install rsyslog -y`).
* Python 3.10 ou superior.
* Acesso à internet para sincronização NTP (`pool.ntp.org`).

### Instalação

1. Clone ou copie o repositório para suas máquinas (Broker e Agentes).
2. Crie e ative um ambiente virtual:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
3. Instale as dependências externas do projeto:
   ```bash
   pip install -r requirements.txt
   ```

### 1. Iniciando o Broker
O Broker não precisa de permissões de administrador (root). Ele deve rodar em uma máquina central e acessível pela rede.
Execute de dentro da pasta `src/`:
```bash
cd src
python3 -m broker.main
```

### 2. Configurando e Iniciando os Agentes
Nos servidores que você deseja proteger, abra o arquivo `src/agent/config.py` e altere a variável `BROKER_HOST` para o endereço IP da máquina onde o Broker está rodando.

Os Agentes **precisam** de permissão root (`sudo`) pois manipulam o Firewall da máquina e leem logs protegidos do sistema.
Execute de dentro da pasta `src/`:
```bash
cd src
sudo python3 -m agent.main --id agent-01
```
*Dica: Em outras máquinas, troque o id (ex: `--id agent-02`).*

### 3. Service Discovery (Descoberta Automática de Rede)
O sistema possui **Service Discovery**:
* Quando um Agente inicia, ele se registra no Broker.
* O Broker atua como um Diretório/Lista Telefônica.
* Toda vez que um Agente entra ou sai da rede (detectado via falha de Heartbeat), o Broker envia uma mensagem `peer_update` para todos os sobreviventes.
* Assim, todos os Agentes conhecem a topologia atual e estão prontos para iniciar a eleição caso o Broker caia, de forma 100% dinâmica.

Você só precisa garantir o IP original do Broker no `src/agent/config.py`:
```python
# IP do Broker original (para Recovery Probe / Failback)
ORIGINAL_BROKER_HOST = "192.168.1.100"
```

### 🧪 Como Testar o Sistema na Prática

1. Inicie o **Broker** (Terminal 1).
2. Inicie o **Agente 01** (Terminal 2).
3. Inicie o **Agente 02** (Terminal 3).
4. De um computador externo (ou outro terminal local usando SSH), tente fazer login no servidor do **Agente 01** com uma senha errada 5 vezes seguidas:
   ```bash
   ssh usuario_invalido@IP_DO_AGENTE_01
   ```
5. **O que vai acontecer:**
   * O LogMonitor do **Agente 01** detectará as falhas.
   * O BanManager do **Agente 01** bloqueará o IP no Firewall local (`iptables -A INPUT -s IP -j DROP`).
   * O **Agente 01** enviará via TCP o alerta ao **Broker**.
   * O **Broker** fará o broadcast desse alerta para o **Agente 02**.
   * O **Agente 02** receberá o alerta e, de forma preventiva, aplicará a mesma regra no seu próprio `iptables`, bloqueando o IP antes mesmo de ser atacado.
   * Em ambos os agentes, após 1 hora (configuração padrão), a regra será removida usando precisão de tempo atômico (NTP).

---
*Projeto desenvolvido por Hugo Martins (Universidade Federal do Pará).*
