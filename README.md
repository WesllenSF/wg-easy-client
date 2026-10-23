# wg-easy-client

Gerenciador de túneis **WireGuard (cliente)** com página web, feito para rodar em Docker no
Linux. A ideia é ser o equivalente ao cliente oficial do Windows, só que pelo navegador do
PC ou do celular.

> Projeto independente: não tem relação com o `wg-easy` (que é um *servidor* WireGuard).

## Funcionalidades

| Cliente Windows | wg-easy-client |
|---|---|
| Lista de túneis com status | ✅ ponto verde no túnel ativo |
| Ativar / desativar | ✅ ativar um túnel desativa o outro automaticamente |
| Importar túnel de arquivo (`.conf` ou `.zip`) | ✅ vários arquivos de uma vez |
| Adicionar túnel vazio (gera par de chaves) | ✅ com modelo pronto |
| Editar nome e configuração, chave pública ao vivo | ✅ |
| Bloquear tráfego fora do túnel (kill-switch) | ✅ via iptables |
| Excluir túnel | ✅ |
| Exportar todos os túneis em `.zip` | ✅ |
| Detalhes da interface e dos peers | ✅ handshake e transferência atualizados a cada 2 s |
| Log | ✅ aba **Log** (mostra o que o `wg-quick` executou) |
| Iniciar com o sistema | ✅ o último túnel ativo volta sozinho quando o contêiner sobe |
| Bloqueio de scripts PreUp/PostUp | ✅ bloqueados, a não ser que `WGEC_ALLOW_SCRIPTS=1` |

Extras: senha de acesso, tema claro/escuro automático, layout para celular (lista → detalhes,
botão voltar do Android funciona) e pode ser adicionado à tela inicial como app.

## Leve

- Só **Python (biblioteca padrão)** + `wireguard-tools` + `iptables` em Alpine. Sem
  frameworks, sem Node, sem banco de dados.
- O servidor fica parado esperando requisições (~18 MB de RAM). A página só consulta o
  status enquanto está aberta e visível.
- A página inteira tem um único arquivo de ~27 KB (~9 KB com gzip).
- O `docker-compose.yml` limita o contêiner a 64 MB de RAM e meia CPU.

## Instalação (Debian)

1. Docker instalado e o módulo WireGuard disponível (Debian 11/12 já trazem):
   ```bash
   sudo modprobe wireguard
   ```
2. Deixe ligado no host um ajuste de que o `wg-quick` precisa (o contêiner não pode alterar
   isso sozinho):
   ```bash
   echo 'net.ipv4.conf.all.src_valid_mark=1' | sudo tee /etc/sysctl.d/99-wg-easy-client.conf
   ```
   ```bash
   sudo sysctl --system
   ```
3. Não precisa baixar o código. Crie uma pasta, salve nela o `docker-compose.yml` abaixo
   e troque a senha:
   ```bash
   mkdir -p ~/wg-easy-client && cd ~/wg-easy-client && nano docker-compose.yml
   ```
   ```yaml
   services:
     wg-easy-client:
       image: ghcr.io/wesllensf/wg-easy-client:latest
       container_name: wg-easy-client
       network_mode: host
       cap_add:
         - NET_ADMIN
       environment:
         - WGEC_PASSWORD=troque-esta-senha
       volumes:
         - ./config:/config
       restart: unless-stopped
       mem_limit: 64m
   ```
   Depois suba o contêiner (a imagem é baixada automaticamente):
   ```bash
   docker compose up -d
   ```
   Se preferir não deixar a senha no compose, use `WGEC_PASSWORD=${WGEC_PASSWORD}` e coloque
   o valor num arquivo `.env` na mesma pasta (veja o `.env.example`).
4. Abra `http://<IP-do-servidor>:51821`, importe seus `.conf` e clique em **Ativar**.

Para atualizar para a versão mais nova:

```bash
docker compose pull && docker compose up -d
```

Imagens disponíveis para `amd64`, `arm64` e `arm/v7` (Raspberry Pi).

Os túneis ficam em `./config/tunnels/*.conf` (permissão 600). Faça backup dessa pasta, mas
nunca a publique: ela tem as chaves privadas (por isso está no `.gitignore`).

## Variáveis de ambiente

| Variável | Padrão | Para quê |
|---|---|---|
| `WGEC_PASSWORD` | (vazio) | Senha da página, definida no `.env`. Vazia: a senha é criada no primeiro acesso. |
| `WGEC_PORT` | `51821` | Porta da página. |
| `WGEC_HOST` | `0.0.0.0` | Endereço em que a página escuta (`127.0.0.1` = só no próprio PC). |
| `WGEC_ALLOW_SCRIPTS` | (vazio) | `1` libera PreUp/PostUp/PreDown/PostDown (rodam como root no host). |
| `WGEC_IPTABLES` | (vazio) | `legacy` se o host usa iptables-legacy em vez de nftables. |
| `WGEC_MOCK` | (vazio) | `1` simula o WireGuard (para testar a página sem root). |

## Como funciona

- O contêiner usa a **rede do host** (`network_mode: host`) com `NET_ADMIN`. Assim o túnel
  vale para o computador inteiro, igual ao cliente do Windows.
- Ativar chama `wg-quick up`, desativar chama `wg-quick down`. Só um túnel fica ativo por vez.
- Ao parar o contêiner, o túnel é desativado. Ao subir de novo, o último túnel ativo é
  reativado.

### Kill-switch

Quando marcado no editor, cria a cadeia `WGEC_KILLSWITCH` na `OUTPUT` do iptables (IPv4 e
IPv6). Ela bloqueia todo tráfego que sai do host fora do túnel, exceto:

- loopback;
- o próprio tráfego criptografado do WireGuard;
- **respostas** a conexões que chegaram de fora (para a página e o SSH continuarem
  acessíveis pela rede local).

Só faz sentido em túneis com `AllowedIPs = 0.0.0.0/0, ::/0`. Se o kill-switch não puder ser
aplicado, o túnel não é ativado (falha segura). Ele não bloqueia tráfego roteado (`FORWARD`)
de outras máquinas.

### DNS

A linha `DNS =` do `.conf` é aplicada no `/etc/resolv.conf` do contêiner. Para valer no host
inteiro, descomente no compose:

```yaml
- /etc/resolv.conf:/host/resolv.conf
```

O arquivo original é guardado e restaurado ao desativar. Se o host usa `systemd-resolved` ou
o NetworkManager reescreve o `resolv.conf`, prefira configurar o DNS por eles.

## Segurança

- A página não tem HTTPS. Na rede local tudo bem; para acesso de fora use um proxy reverso
  com HTTPS (ele precisa repassar `X-Forwarded-Proto: https`) ou um túnel SSH:
  ```bash
  ssh -L 51821:localhost:51821 usuario@servidor
  ```
- Quem acessa a página tem as chaves privadas dos túneis. Use uma senha forte.
- Não acesse a página através do próprio túnel que você vai trocar: a conexão cai na troca.

## Desenvolvimento

A cada push na branch principal, o GitHub Actions ([docker.yml](.github/workflows/docker.yml))
roda os testes e publica a imagem `latest` no `ghcr.io`. Uma tag `v1.2.3` publica também as
tags `1.2.3` e `1.2`.

Para montar a imagem a partir do código local, troque `image:` por `build: .` no
`docker-compose.yml` e rode `docker compose up -d --build`.

Testes (não precisam de root nem de WireGuard):

```bash
python3 -m unittest discover tests -v
```

Rodar a página em modo simulado:

```bash
WGEC_MOCK=1 WGEC_DATA=./dev-data python3 app/server.py
```

Estrutura:

```
app/core.py          chaves (X25519), validação do .conf, wg-quick, kill-switch, importação
app/server.py        HTTP, API JSON, login
app/static/          página (HTML/CSS/JS num arquivo só), ícone e manifest
rootfs/.../resolvconf  substituto do resolvconf para a linha DNS =
```

## Licença

[MIT](LICENSE)
