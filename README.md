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
O Agente roda em cada servidor que precisa ser protegido. Ele é altamente paralelo, dividido em 4 *Threads* principais:
- **LogMonitor (Detecção):** Fica lendo continuamente o arquivo `/var/log/auth.log` (técnica *tail -f*). Ao detectar 5 falhas de SSH do mesmo IP em 10 minutos, dispara um alerta de bloqueio.
- **NetworkListener (Comunicação TCP):** Mantém uma conexão persistente com o Broker para receber alertas de ataques detectados por outros servidores da rede.
- **HeartbeatSender (Monitoramento UDP):** Envia pacotes leves (UDP) a cada 10 segundos para avisar ao Broker que o servidor está online.
- **BanManager (Firewall & NTP):** Executa os comandos reais do `iptables` para bloquear pacotes de rede do atacante. Ele também agenda o desbloqueio automático (auto-unban).

### 📡 Protocolos de Rede e Sistemas Distribuídos Utilizados

Para fins didáticos e técnicos, o sistema implementa protocolos de rede "na unha" (raw sockets):
* **TCP com Length-Prefix Framing:** Usado para envio de Alertas. Resolve o problema de fragmentação do TCP enviando 4 bytes de cabeçalho indicando o tamanho exato da mensagem JSON a ser lida.
* **UDP (Fire and Forget):** Usado para os Heartbeats. Sendo rápido e sem conexão, é ideal para enviar avisos periódicos de "estou vivo" sem sobrecarregar a rede.
* **NTP (Network Time Protocol):** Em sistemas distribuídos, relógios locais dessincronizados causam problemas graves. O sistema consulta servidores globais (pool.ntp.org) para calcular o momento exato em que um IP deve ser desbloqueado. Isso garante que todos os servidores da rede desbloqueiem o atacante exatamente no mesmo segundo.

---

## 🚀 Como Utilizar (Guia de Execução)

### Pré-requisitos
* Máquinas Virtuais (ou instâncias locais/cloud) rodando **Linux (Debian ou Ubuntu)**.
* Serviço **SSH** rodando nas máquinas dos Agentes (`sudo apt install openssh-server`).
* **iptables** instalado (`sudo apt install iptables`).
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
# Ative o ambiente virtual logado como sudo, ou execute usando o interpretador do venv:
sudo ../.venv/bin/python -m agent.main --id agent-01
```
*Dica: Em outras máquinas, troque o id (ex: `--id agent-02`).*

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
