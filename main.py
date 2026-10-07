import os
import re
import time
import uuid
import shutil
import sqlite3
import threading
import queue
import datetime
import requests
import urllib3
import paramiko
import xml.etree.ElementTree as ET
import customtkinter as ctk
from dotenv import load_dotenv
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
import base64

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

fila_log = queue.Queue()

PASTA_CLIENTES = "./clientes"
PASTA_ARQUIVADOS = "./clientes/_arquivados"
DB_PATH = "./clientes.db"


# ============================================================
# BANCO DE DADOS
# ============================================================
class DB:
    def __init__(self, path=DB_PATH):
        self.path = path
        self.lock = threading.Lock()
        self._init_db()

    def _conn(self):
        conn = sqlite3.connect(self.path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self.lock:
            conn = self._conn()
            cur = conn.cursor()
            cur.executescript("""
                CREATE TABLE IF NOT EXISTS clientes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    nome TEXT UNIQUE NOT NULL,
                    tag_vlan INTEGER,
                    uuid_vlan TEXT,
                    vlanif TEXT,
                    opt_vlan TEXT,
                    opt_wg TEXT,
                    uuid_servidor_wg TEXT,
                    nome_servidor_wg TEXT,
                    porta_wg INTEGER,
                    tunel_wg TEXT,
                    pasta_conf TEXT,
                    status TEXT DEFAULT 'criando',
                    criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    atualizado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS peers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cliente_id INTEGER NOT NULL,
                    nome_peer TEXT NOT NULL,
                    uuid_peer TEXT,
                    tunel_peer TEXT,
                    arquivo_conf TEXT,
                    FOREIGN KEY (cliente_id) REFERENCES clientes(id)
                );
                CREATE TABLE IF NOT EXISTS regras_firewall (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cliente_id INTEGER NOT NULL,
                    uuid_regra TEXT,
                    descricao TEXT,
                    FOREIGN KEY (cliente_id) REFERENCES clientes(id)
                );
            """)
            conn.commit()
            conn.close()

    def criar_cliente(self, nome):
        with self.lock:
            conn = self._conn()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO clientes (nome, status) VALUES (?, 'criando')",
                (nome,)
            )
            cliente_id = cur.lastrowid
            conn.commit()
            conn.close()
            return cliente_id

    def atualizar_cliente(self, cliente_id, **campos):
        if not campos:
            return
        with self.lock:
            conn = self._conn()
            sets = ", ".join(f"{k} = ?" for k in campos)
            vals = list(campos.values()) + [cliente_id]
            conn.execute(
                f"UPDATE clientes SET {sets}, atualizado_em = CURRENT_TIMESTAMP WHERE id = ?",
                vals
            )
            conn.commit()
            conn.close()

    def set_status(self, cliente_id, status):
        self.atualizar_cliente(cliente_id, status=status)

    def buscar_cliente_por_id(self, cliente_id):
        with self.lock:
            conn = self._conn()
            cur = conn.execute("SELECT * FROM clientes WHERE id = ?", (cliente_id,))
            row = cur.fetchone()
            conn.close()
            return dict(row) if row else None

    def buscar_cliente_por_nome(self, nome):
        with self.lock:
            conn = self._conn()
            cur = conn.execute("SELECT * FROM clientes WHERE nome = ?", (nome,))
            row = cur.fetchone()
            conn.close()
            return dict(row) if row else None

    def listar_clientes(self, status=None):
        with self.lock:
            conn = self._conn()
            if status:
                cur = conn.execute("SELECT * FROM clientes WHERE status = ? ORDER BY id DESC", (status,))
            else:
                cur = conn.execute("SELECT * FROM clientes ORDER BY id DESC")
            rows = [dict(r) for r in cur.fetchall()]
            conn.close()
            return rows

    def adicionar_peer(self, cliente_id, nome_peer, uuid_peer, tunel, arquivo):
        with self.lock:
            conn = self._conn()
            conn.execute(
                "INSERT INTO peers (cliente_id, nome_peer, uuid_peer, tunel_peer, arquivo_conf) VALUES (?, ?, ?, ?, ?)",
                (cliente_id, nome_peer, uuid_peer, tunel, arquivo)
            )
            conn.commit()
            conn.close()

    def listar_peers(self, cliente_id):
        with self.lock:
            conn = self._conn()
            cur = conn.execute("SELECT * FROM peers WHERE cliente_id = ?", (cliente_id,))
            rows = [dict(r) for r in cur.fetchall()]
            conn.close()
            return rows

    def adicionar_regra(self, cliente_id, uuid_regra, descricao):
        with self.lock:
            conn = self._conn()
            conn.execute(
                "INSERT INTO regras_firewall (cliente_id, uuid_regra, descricao) VALUES (?, ?, ?)",
                (cliente_id, uuid_regra, descricao)
            )
            conn.commit()
            conn.close()

    def listar_regras(self, cliente_id):
        with self.lock:
            conn = self._conn()
            cur = conn.execute("SELECT * FROM regras_firewall WHERE cliente_id = ?", (cliente_id,))
            rows = [dict(r) for r in cur.fetchall()]
            conn.close()
            return rows

    def remover_cliente(self, cliente_id):
        with self.lock:
            conn = self._conn()
            conn.execute("DELETE FROM peers WHERE cliente_id = ?", (cliente_id,))
            conn.execute("DELETE FROM regras_firewall WHERE cliente_id = ?", (cliente_id,))
            conn.execute("DELETE FROM clientes WHERE id = ?", (cliente_id,))
            conn.commit()
            conn.close()


# ============================================================
# BACKEND
# ============================================================
class Backend:
    def __init__(self, db):
        self.db = db
        self.opnsense_url = os.getenv("OPNSENSE_URL")
        self.opnsense_auth = (
            os.getenv("OPNSENSE_API_KEY"),
            os.getenv("OPNSENSE_API_SECRET")
        )
        self.interface_pai = os.getenv("OPNSENSE_INTERFACE_PAI", "em0")
        self.ssh_host = os.getenv("OPNSENSE_SSH_HOST", "177.10.1.241")
        self.ssh_user = os.getenv("OPNSENSE_SSH_USER", "root")
        self.ssh_senha = os.getenv("OPNSENSE_SSH_PASS")
        self.wan_ip = os.getenv("OPNSENSE_WAN_IP", "177.10.1.241")

        if not all([self.opnsense_url, self.opnsense_auth[0], self.opnsense_auth[1]]):
            raise Exception("Credenciais de API faltando no .env")
        if not self.ssh_senha:
            raise Exception("OPNSENSE_SSH_PASS faltando no .env")

    # ========================================================
    # HELPERS
    # ========================================================
    @staticmethod
    def gerar_par_chaves():
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()

        private_b64 = base64.b64encode(
            private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
        ).decode()

        public_b64 = base64.b64encode(
            public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        ).decode()

        return private_b64, public_b64

    # ========================================================
    # API REST — VLANs
    # ========================================================
    def listar_vlans(self):
        r = requests.get(
            f"{self.opnsense_url}/api/interfaces/vlan_settings/searchItem",
            auth=self.opnsense_auth, verify=False, timeout=15
        )
        if r.status_code != 200:
            raise Exception(f"HTTP {r.status_code} - {r.text}")
        return r.json().get("rows", [])

    def proxima_tag(self):
        vlans = self.listar_vlans()
        tags = [int(v["tag"]) for v in vlans if v.get("tag", "").isdigit()]
        if not tags:
            return 10
        return ((max(tags) // 10) + 1) * 10

    def criar_vlan_api(self, tag, descricao):
        vlanif = f"vlan0.{tag}"
        payload = {
            "vlan": {
                "if": self.interface_pai,
                "tag": str(tag),
                "pcp": "0",
                "proto": "",
                "descr": descricao,
                "vlanif": vlanif
            }
        }
        r = requests.post(
            f"{self.opnsense_url}/api/interfaces/vlan_settings/addItem",
            auth=self.opnsense_auth, json=payload, verify=False, timeout=15
        )
        if r.status_code != 200:
            raise Exception(f"Falha ao criar VLAN: HTTP {r.status_code} - {r.text}")
        resp = r.json()
        if resp.get("result") != "saved":
            raise Exception(f"VLAN não foi salva: {resp}")

        requests.post(
            f"{self.opnsense_url}/api/interfaces/vlan_settings/reconfigure",
            auth=self.opnsense_auth, verify=False, timeout=15
        )
        return vlanif

    def excluir_vlan_api(self, uuid_vlan):
        """Retorna True/False. NÃO levanta exceção."""
        try:
            r = requests.post(
                f"{self.opnsense_url}/api/interfaces/vlan_settings/delItem/{uuid_vlan}",
                auth=self.opnsense_auth, verify=False, timeout=15
            )
            if r.status_code != 200:
                return False
            requests.post(
                f"{self.opnsense_url}/api/interfaces/vlan_settings/reconfigure",
                auth=self.opnsense_auth, verify=False, timeout=15
            )
            return True
        except Exception:
            return False

    # ========================================================
    # API REST — WireGuard
    # ========================================================
    def listar_servidores_wg(self):
        r = requests.get(
            f"{self.opnsense_url}/api/wireguard/server/searchServer",
            auth=self.opnsense_auth, verify=False, timeout=15
        )
        if r.status_code != 200:
            return []
        return r.json().get("rows", [])

    def listar_clientes_wg(self):
        r = requests.get(
            f"{self.opnsense_url}/api/wireguard/client/searchClient",
            auth=self.opnsense_auth, verify=False, timeout=15
        )
        if r.status_code != 200:
            return []
        return r.json().get("rows", [])

    def criar_servidor_wg(self, nome, porta, tunel):
        """Cria servidor WG. Gera a privkey localmente porque a API não gera."""
        privkey, pubkey = self.gerar_par_chaves()

        payload = {
            "server": {
                "enabled": "1",
                "name": nome,
                "port": str(porta),
                "tunneladdress": tunel,
                "disableroutes": "0",
                "peers": "",
                "dns": "",
                "mtu": "",
                "gateway": "",
                "carp_depend_on": "",
                "debug": "0",
                "privkey": privkey,
                "pubkey": pubkey
            }
        }
        r = requests.post(
            f"{self.opnsense_url}/api/wireguard/server/addServer",
            auth=self.opnsense_auth, json=payload, verify=False, timeout=15
        )
        if r.status_code != 200:
            raise Exception(f"Falha ao criar servidor WG: HTTP {r.status_code} - {r.text}")

        resp = r.json()
        if resp.get("result") != "saved":
            raise Exception(f"Servidor WG não foi salvo: {resp}")

        # A API retorna o UUID direto. Fallback pro retry.
        uuid_servidor = resp.get("uuid")
        if uuid_servidor:
            for s in self.listar_servidores_wg():
                if s.get("uuid") == uuid_servidor:
                    return uuid_servidor, s.get("pubkey", pubkey)

        for tentativa in range(30):
            time.sleep(1)
            for s in self.listar_servidores_wg():
                if s.get("name") == nome:
                    return s.get("uuid"), s.get("pubkey")

        raise Exception(f"Servidor {nome} criado mas não encontrado após 30 tentativas.")

    def excluir_servidor_wg(self, uuid_servidor):
        try:
            requests.post(
                f"{self.opnsense_url}/api/wireguard/server/delServer/{uuid_servidor}",
                auth=self.opnsense_auth, verify=False, timeout=15
            )
            return True
        except Exception:
            return False

    def criar_peer_wg(self, nome, pubkey_cliente, tunel_cliente):
        payload = {
            "client": {
                "enabled": "1",
                "name": nome,
                "pubkey": pubkey_cliente,
                "tunneladdress": tunel_cliente,
                "persistentkeepalive": "25"
            }
        }
        r = requests.post(
            f"{self.opnsense_url}/api/wireguard/client/addClient",
            auth=self.opnsense_auth, json=payload, verify=False, timeout=15
        )
        if r.status_code != 200:
            raise Exception(f"Falha ao criar peer: HTTP {r.status_code} - {r.text}")

        for tentativa in range(5):
            time.sleep(1)
            for c in self.listar_clientes_wg():
                if c.get("name") == nome:
                    return c.get("uuid")

        raise Exception(f"Peer {nome} criado mas não encontrado")

    def excluir_peer_wg(self, uuid_peer):
        try:
            requests.post(
                f"{self.opnsense_url}/api/wireguard/client/delClient/{uuid_peer}",
                auth=self.opnsense_auth, verify=False, timeout=15
            )
            return True
        except Exception:
            return False

    def vincular_peer_ao_servidor(self, uuid_servidor, uuid_peer):
        """Vincula peer ao servidor. O OPNsense espera um dict, não string."""
        # Busca os peers atuais do servidor
        peers_atuais = []
        for s in self.listar_servidores_wg():
            if s.get("uuid") == uuid_servidor:
                peers_str = s.get("peers", "")
                if peers_str:
                    peers_atuais = [p.strip() for p in peers_str.split(",") if p.strip()]
                break
        else:
            raise Exception(f"Servidor {uuid_servidor} não encontrado")

        # Adiciona o novo peer
        if uuid_peer not in peers_atuais:
            peers_atuais.append(uuid_peer)

        # Monta o dict no formato que a API espera
        peers_dict = {u: {"selected": "1"} for u in peers_atuais}

        payload = {
            "server": {
                "uuid": uuid_servidor,
                "peers": peers_dict
            }
        }
        r = requests.post(
            f"{self.opnsense_url}/api/wireguard/server/set",
            auth=self.opnsense_auth, json=payload, verify=False, timeout=15
        )
        if r.status_code != 200:
            raise Exception(f"Falha ao vincular peer: HTTP {r.status_code} - {r.text}")

        resp = r.json()
        if resp.get("result") != "saved":
            raise Exception(f"Peer não foi vinculado: {resp}")

    # ========================================================
    # API REST — Firewall
    # ========================================================
    def criar_regra_firewall(self, opt_nome, rede_origem, descricao):
        payload = {
            "rule": {
                "description": descricao,
                "interface": opt_nome,
                "ipprotocol": "inet",
                "protocol": "any",
                "source_net": rede_origem,
                "destination_net": "any",
                "action": "pass",
                "direction": "in",
                "statetype": "keep state",
                "quick": "1"
            }
        }
        r = requests.post(
            f"{self.opnsense_url}/api/firewall/filter/addRule",
            auth=self.opnsense_auth, json=payload, verify=False, timeout=15
        )
        if r.status_code != 200:
            raise Exception(f"Falha ao criar regra: HTTP {r.status_code} - {r.text}")

        try:
            resp = r.json()
            uuid_regra = resp.get("uuid")
            if uuid_regra:
                return uuid_regra
        except Exception:
            pass

        time.sleep(1)
        r2 = requests.get(
            f"{self.opnsense_url}/api/firewall/filter/searchRule",
            auth=self.opnsense_auth, verify=False, timeout=15
        )
        if r2.status_code == 200:
            for regra in r2.json().get("rows", []):
                if regra.get("description") == descricao:
                    return regra.get("uuid")

        return None

    def excluir_regra_firewall(self, uuid_regra):
        try:
            requests.post(
                f"{self.opnsense_url}/api/firewall/filter/delRule/{uuid_regra}",
                auth=self.opnsense_auth, verify=False, timeout=15
            )
            return True
        except Exception:
            return False

    def aplicar_firewall(self):
        try:
            requests.post(
                f"{self.opnsense_url}/api/firewall/filter/apply",
                auth=self.opnsense_auth, verify=False, timeout=15
            )
        except Exception:
            pass

    # ========================================================
    # SSH — config.xml
    # ========================================================
    def _ssh(self):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=self.ssh_host,
            username=self.ssh_user,
            password=self.ssh_senha,
            timeout=15
        )
        return ssh

    def _ssh_exec(self, ssh, cmd):
        try:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            return stdout.read().decode(), stderr.read().decode()
        except Exception:
            return "", ""

    def _ler_config_xml(self, ssh):
        sftp = ssh.open_sftp()
        with sftp.file("/conf/config.xml", "r") as f:
            return f.read().decode()

    def _escrever_config_xml(self, ssh, conteudo):
        sftp = ssh.open_sftp()
        with sftp.file("/conf/config.xml", "w") as f:
            f.write(conteudo)

    def _backup_config_xml(self, ssh, sufixo):
        try:
            sftp = ssh.open_sftp()
            with sftp.file("/conf/config.xml", "r") as f:
                conteudo = f.read().decode()
            with sftp.file(f"/conf/config.xml.bak_{sufixo}", "w") as f:
                f.write(conteudo)
        except Exception:
            pass

    def _proximo_opt(self, xml_content):
        root = ET.fromstring(xml_content)
        interfaces = root.find("interfaces")
        if interfaces is None:
            return 5
        usados = []
        for child in interfaces:
            m = re.match(r"^opt(\d+)$", child.tag)
            if m:
                usados.append(int(m.group(1)))
        return max(usados) + 1 if usados else 5

    def _inserir_interface_xml(self, xml_content, opt_nome, iface_device, descr, ip=None):
        root = ET.fromstring(xml_content)
        interfaces = root.find("interfaces")
        if interfaces is None:
            raise Exception("<interfaces> não encontrado")

        opt = ET.SubElement(interfaces, opt_nome)
        ET.SubElement(opt, "if").text = iface_device
        ET.SubElement(opt, "descr").text = descr
        ET.SubElement(opt, "enable").text = "1"
        ET.SubElement(opt, "spoofmac").text = None
        if ip:
            ET.SubElement(opt, "lock").text = "1"
            ET.SubElement(opt, "ipaddr").text = ip
            ET.SubElement(opt, "subnet").text = "24"

        return ET.tostring(root, encoding="unicode", xml_declaration=True)

    def _remover_interface_opt_xml(self, xml_content, device):
        """Remove o <optN> que aponta pro device (ex: 'vlan0.40', 'wg2')."""
        root = ET.fromstring(xml_content)
        interfaces = root.find("interfaces")
        if interfaces is None:
            return xml_content, None

        opt_removido = None
        for child in interfaces:
            if child.tag.startswith("opt"):
                if_elem = child.find("if")
                if if_elem is not None and if_elem.text == device:
                    opt_removido = child.tag
                    interfaces.remove(child)
                    break

        return ET.tostring(root, encoding="unicode", xml_declaration=True), opt_removido

    # ========================================================
    # CRIAÇÃO COMPLETA
    # ========================================================
    def criar_cliente_completo(self, nome_cliente, num_peers, log_callback, forcar=False):
        nome_cliente = nome_cliente.strip().upper().replace(" ", "-")
        descricao = f"VLAN_{nome_cliente}"
        ssh = None

        cliente_existente = self.db.buscar_cliente_por_nome(nome_cliente)
        if cliente_existente and not forcar:
            raise Exception(f"Cliente {nome_cliente} já existe no banco.")

        cliente_id = self.db.criar_cliente(nome_cliente)

        pasta_cliente = os.path.join(PASTA_CLIENTES, f"{nome_cliente}-vpn-peers")
        os.makedirs(PASTA_CLIENTES, exist_ok=True)
        os.makedirs(pasta_cliente, exist_ok=True)

        try:
            # 1. Próxima tag
            log_callback("[1/8] Lendo VLANs existentes...")
            tag = self.proxima_tag()
            vlanif = f"vlan0.{tag}"
            ip_vlan = f"10.10.{tag}.1"
            rede_vlan = f"10.10.{tag}.0/24"
            self.db.atualizar_cliente(cliente_id, tag_vlan=tag, vlanif=vlanif)
            log_callback(f"      VLAN {tag} | {vlanif} | {ip_vlan}/24")

            # 2. SSH + próximo opt
            log_callback("[2/8] Conectando via SSH...")
            ssh = self._ssh()
            xml_atual = self._ler_config_xml(ssh)
            opt_vlan_num = self._proximo_opt(xml_atual)
            opt_vlan = f"opt{opt_vlan_num}"
            opt_wg = f"opt{opt_vlan_num + 1}"
            self.db.atualizar_cliente(cliente_id, opt_vlan=opt_vlan, opt_wg=opt_wg)
            log_callback(f"      Interface VLAN: {opt_vlan} | Interface WG: {opt_wg}")

            # 3. Próximo WireGuard — CORRIGIDO (bug 2)
            log_callback("[3/8] Lendo servidores WireGuard...")
            servidores = self.listar_servidores_wg()
            instancias = []
            for s in servidores:
                try:
                    instancias.append(int(s.get("instance", 0)))
                except (ValueError, TypeError):
                    pass
            prox_wg_num = max(instancias) + 1 if instancias else 0
            wg_nome = f"WG_{nome_cliente}"
            wg_porta = 51820 + (prox_wg_num * 2)
            wg_tunel = f"10.{tag}.{tag}.1/24"
            wg_rede = f"10.{tag}.{tag}.0/24"
            self.db.atualizar_cliente(
                cliente_id,
                nome_servidor_wg=wg_nome,
                porta_wg=wg_porta,
                tunel_wg=wg_tunel
            )
            log_callback(f"      Servidor {wg_nome} | porta {wg_porta} | túnel {wg_tunel}")

            # 4. Criar VLAN
            log_callback(f"[4/8] Criando VLAN {tag} via API...")
            self.criar_vlan_api(tag, descricao)
            for v in self.listar_vlans():
                if str(v.get("tag")) == str(tag):
                    self.db.atualizar_cliente(cliente_id, uuid_vlan=v.get("uuid"))
                    break
            log_callback(f"      VLAN {tag} criada.")

            # 5. Editar XML
            log_callback("[5/8] Editando config.xml...")
            self._backup_config_xml(ssh, f"vlan{tag}")

            xml_atual = self._ler_config_xml(ssh)
            xml_novo = self._inserir_interface_xml(
                xml_atual, opt_vlan, vlanif, descricao, ip=ip_vlan
            )
            xml_novo = self._inserir_interface_xml(
                xml_novo, opt_wg, f"wg{prox_wg_num}", wg_nome, ip=None
            )
            self._escrever_config_xml(ssh, xml_novo)
            log_callback(f"      XML: {opt_vlan} + {opt_wg} adicionados.")

            # 6. Servidor WG — CORRIGIDO (bugs 1 e 6)
            log_callback(f"[6/8] Criando servidor WireGuard {wg_nome}...")
            uuid_servidor, pubkey_servidor = self.criar_servidor_wg(
                wg_nome, wg_porta, wg_tunel
            )
            self.db.atualizar_cliente(cliente_id, uuid_servidor_wg=uuid_servidor)
            log_callback(f"      Servidor criado (UUID {uuid_servidor[:8]}...)")

            # 7. Peers
            log_callback(f"[7/8] Criando {num_peers} peer(s) WireGuard...")
            for i in range(1, num_peers + 1):
                nome_peer = f"{nome_cliente}-PEER-{i}"
                tunel_peer = f"10.{tag}.{tag}.{i + 1}/32"
                priv, pub = self.gerar_par_chaves()

                uuid_peer = self.criar_peer_wg(nome_peer, pub, tunel_peer)
                self.vincular_peer_ao_servidor(uuid_servidor, uuid_peer)

                conf = self._gerar_conf(priv, tunel_peer, pubkey_servidor, wg_porta)
                caminho_conf = os.path.join(pasta_cliente, f"{nome_peer}.conf")
                with open(caminho_conf, "w") as f:
                    f.write(conf)

                self.db.adicionar_peer(
                    cliente_id, nome_peer, uuid_peer, tunel_peer, caminho_conf
                )
                log_callback(f"      Peer {i}: {caminho_conf}")

            self.aplicar_wireguard()
            log_callback("      WireGuard aplicado.")

            # 8. Firewall
            log_callback("[8/8] Criando regras de firewall...")
            u1 = self.criar_regra_firewall(
                opt_vlan, rede_vlan, f"Internet only - {descricao}"
            )
            if u1:
                self.db.adicionar_regra(cliente_id, u1, f"Internet only - {descricao}")
            u2 = self.criar_regra_firewall(
                opt_vlan, wg_rede, f"VPN {wg_nome} -> {descricao}"
            )
            if u2:
                self.db.adicionar_regra(cliente_id, u2, f"VPN {wg_nome} -> {descricao}")
            self.aplicar_firewall()
            log_callback("      Regras de firewall aplicadas.")

            # Aplicar configctl
            log_callback("[+] Aplicando configctl...")
            for cmd in [
                "configctl interface vlan configure",
                f"configctl interface reconfigure {opt_vlan}",
                f"configctl interface reconfigure {opt_wg}",
                "configctl filter reload"
            ]:
                out, err = self._ssh_exec(ssh, cmd)
                log_callback(f"      $ {cmd}")
                if err.strip():
                    log_callback(f"        stderr: {err.strip()}")

            self.db.set_status(cliente_id, "ativo")

            return {
                "cliente_id": cliente_id,
                "tag": tag,
                "vlanif": vlanif,
                "opt_vlan": opt_vlan,
                "opt_wg": opt_wg,
                "wg_nome": wg_nome,
                "wg_porta": wg_porta,
                "peers": num_peers,
                "pasta": pasta_cliente
            }

        except Exception as e:
            log_callback(f"[ERRO] {e}")
            self.db.set_status(cliente_id, "parcial")
            self._rollback_por_banco(cliente_id, ssh, log_callback)
            raise
        finally:
            if ssh:
                try:
                    ssh.close()
                except Exception:
                    pass

    def _gerar_conf(self, priv, address, pubkey_server, porta):
        return (
            f"[Interface]\n"
            f"PrivateKey = {priv}\n"
            f"Address = {address}\n"
            f"DNS = 8.8.8.8\n\n"
            f"[Peer]\n"
            f"PublicKey = {pubkey_server}\n"
            f"Endpoint = {self.wan_ip}:{porta}\n"
            f"AllowedIPs = 0.0.0.0/0\n"
            f"PersistentKeepalive = 25\n"
        )

    # ========================================================
    # ROLLBACK — CORRIGIDO (bugs 3, 4 e 5)
    # ========================================================
    def _rollback_por_banco(self, cliente_id, ssh, log_callback):
        log_callback("[ROLLBACK] Iniciando limpeza baseada no banco...")

        cli = self.db.buscar_cliente_por_id(cliente_id)
        if not cli:
            log_callback("[ROLLBACK] Cliente não encontrado no banco.")
            return

        # 1. Regras
        regras = self.db.listar_regras(cliente_id)
        if regras:
            log_callback(f"[ROLLBACK] Removendo {len(regras)} regra(s)...")
            for r in regras:
                if r.get("uuid_regra"):
                    self.excluir_regra_firewall(r["uuid_regra"])
            self.aplicar_firewall()

        # 2. Peers
        peers = self.db.listar_peers(cliente_id)
        if peers:
            log_callback(f"[ROLLBACK] Removendo {len(peers)} peer(s)...")
            for p in peers:
                if p.get("uuid_peer"):
                    self.excluir_peer_wg(p["uuid_peer"])

        # 3. Descobre o device do WG ANTES de remover o servidor
        wg_device = None
        if cli.get("nome_servidor_wg"):
            for s in self.listar_servidores_wg():
                if s.get("name") == cli["nome_servidor_wg"]:
                    wg_device = s.get("interface")
                    break

        # 3b. Remove servidor
        if cli.get("uuid_servidor_wg"):
            log_callback("[ROLLBACK] Removendo servidor WG...")
            self.excluir_servidor_wg(cli["uuid_servidor_wg"])
            self.aplicar_wireguard()

        # 4/5. Interfaces
        if ssh and cli.get("vlanif"):
            try:
                xml_atual = self._ler_config_xml(ssh)
                removidas = []

                if wg_device:
                    xml_novo, opt_rm = self._remover_interface_opt_xml(xml_atual, wg_device)
                    if opt_rm:
                        xml_atual = xml_novo
                        removidas.append(opt_rm)

                xml_novo, opt_rm = self._remover_interface_opt_xml(xml_atual, cli["vlanif"])
                if opt_rm:
                    xml_atual = xml_novo
                    removidas.append(opt_rm)

                if removidas:
                    self._escrever_config_xml(ssh, xml_atual)
                    for opt_nome in removidas:
                        self._ssh_exec(ssh, f"configctl interface reconfigure {opt_nome}")
                    self._ssh_exec(ssh, "configctl interface vlan configure")
                    self._ssh_exec(ssh, "configctl filter reload")
                    log_callback(f"[ROLLBACK] Interfaces removidas: {', '.join(removidas)}")
                else:
                    log_callback("[ROLLBACK] Nenhuma interface removida do XML.")
            except Exception as e:
                log_callback(f"[ROLLBACK] Falha ao remover interfaces: {e}")

        # 6. VLAN
        if cli.get("uuid_vlan"):
            log_callback("[ROLLBACK] Removendo VLAN...")
            time.sleep(2)
            ok = False
            for tentativa in range(3):
                ok = self.excluir_vlan_api(cli["uuid_vlan"])
                if ok:
                    break
                time.sleep(3)
            if not ok:
                log_callback("[ROLLBACK] VLAN não pôde ser removida.")

        # 7. Pasta
        pasta = cli.get("pasta_conf") or os.path.join(
            PASTA_CLIENTES, f"{cli['nome']}-vpn-peers"
        )
        if pasta and os.path.exists(pasta):
            try:
                shutil.rmtree(pasta)
                log_callback(f"[ROLLBACK] Pasta {pasta} removida.")
            except Exception as e:
                log_callback(f"[ROLLBACK] Falha ao remover pasta: {e}")

        self.db.remover_cliente(cliente_id)
        log_callback("[ROLLBACK] Limpeza concluída.")

    # ========================================================
    # EXCLUSÃO COMPLETA (BASEADA NO BANCO)
    # ========================================================
    def excluir_cliente_por_id(self, cliente_id, log_callback):
        cliente = self.db.buscar_cliente_por_id(cliente_id)
        if not cliente:
            raise Exception(f"Cliente ID {cliente_id} não encontrado no banco.")

        nome = cliente["nome"]
        ssh = None
        vlan_removida = True

        try:
            log_callback(f"[DEL] Excluindo cliente {nome} (ID {cliente_id})...")

            # 1. Regras de firewall
            regras = self.db.listar_regras(cliente_id)
            if regras:
                log_callback(f"[DEL] 1/7 Removendo {len(regras)} regra(s)...")
                for r in regras:
                    if r.get("uuid_regra"):
                        self.excluir_regra_firewall(r["uuid_regra"])
                self.aplicar_firewall()

            # 2. Peers WG
            peers = self.db.listar_peers(cliente_id)
            if peers:
                log_callback(f"[DEL] 2/7 Removendo {len(peers)} peer(s)...")
                for p in peers:
                    if p.get("uuid_peer"):
                        self.excluir_peer_wg(p["uuid_peer"])

            # 3. Descobre o device do WG ANTES de remover o servidor
            wg_device = None
            if cliente.get("nome_servidor_wg"):
                for s in self.listar_servidores_wg():
                    if s.get("name") == cliente["nome_servidor_wg"]:
                        wg_device = s.get("interface")  # ex: "wg2"
                        break
            if wg_device:
                log_callback(f"      Device do WG descoberto: {wg_device}")

            # 3b. Remove servidor WG
            if cliente.get("uuid_servidor_wg"):
                log_callback("[DEL] 3/7 Removendo servidor WG...")
                self.excluir_servidor_wg(cliente["uuid_servidor_wg"])
                self.aplicar_wireguard()

            # 4. Interfaces (usa o wg_device já descoberto)
            removidas = []
            if cliente.get("vlanif"):
                log_callback("[DEL] 4/7 Removendo interfaces do XML...")
                ssh = self._ssh()
                self._backup_config_xml(ssh, f"del_{nome}")
                xml_atual = self._ler_config_xml(ssh)

                # -------- Interface WG --------
                if wg_device:
                    xml_novo, opt_rm = self._remover_interface_opt_xml(xml_atual, wg_device)
                    if opt_rm:
                        xml_atual = xml_novo
                        removidas.append(opt_rm)
                        log_callback(f"      {opt_rm} (WG, device {wg_device}) removida do XML.")
                    else:
                        log_callback(f"      Nenhuma interface apontando pro {wg_device} no XML.")
                else:
                    log_callback("      Device do WG não descoberto, pulando interface WG.")

                # -------- Interface VLAN --------
                xml_novo, opt_rm = self._remover_interface_opt_xml(xml_atual, cliente["vlanif"])
                if opt_rm:
                    xml_atual = xml_novo
                    removidas.append(opt_rm)
                    log_callback(f"      {opt_rm} (VLAN, device {cliente['vlanif']}) removida do XML.")
                else:
                    log_callback(f"      Nenhuma interface apontando pro {cliente['vlanif']} no XML.")

                if removidas:
                    self._escrever_config_xml(ssh, xml_atual)
                else:
                    log_callback("      NENHUMA interface foi removida do XML!")

            # 5. Reconfigure (só se removeu algo)
            if removidas:
                log_callback("[DEL] 5/7 Recarregando interfaces e VLANs...")
                for opt_nome in removidas:
                    self._ssh_exec(ssh, f"configctl interface reconfigure {opt_nome}")
                self._ssh_exec(ssh, "configctl interface vlan configure")
                self._ssh_exec(ssh, "configctl filter reload")
                time.sleep(2)
            else:
                log_callback("[DEL] 5/7 Nada pra recarregar.")

            # 6. VLAN (com retry)
            if cliente.get("uuid_vlan"):
                log_callback("[DEL] 6/7 Excluindo VLAN...")
                ok = False
                for tentativa in range(3):
                    ok = self.excluir_vlan_api(cliente["uuid_vlan"])
                    if ok:
                        break
                    log_callback(f"      Tentativa {tentativa + 1} falhou, aguardando...")
                    time.sleep(3)
                if ok:
                    log_callback("[DEL] VLAN excluída.")
                else:
                    log_callback("[DEL] VLAN não pôde ser removida após 3 tentativas.")
                    log_callback("[DEL] Cliente ficará como 'parcial' no banco.")
                    vlan_removida = False
            else:
                log_callback("[DEL] 6/7 Nenhuma VLAN registrada. Pulando.")

            # 7. Banco (só remove se a VLAN saiu)
            if vlan_removida:
                log_callback("[DEL] 7/7 Removendo do banco...")
                self.db.remover_cliente(cliente_id)
                log_callback(f"[DEL] Cliente {nome} removido com sucesso.")
            else:
                self.db.set_status(cliente_id, "parcial")
                log_callback(f"[DEL] Cliente {nome} marcado como 'parcial' no banco.")
                log_callback("[DEL] Remove a VLAN manualmente pela GUI e tente de novo.")

            return {"nome_cliente": nome, "cliente_id": cliente_id}

        finally:
            if ssh:
                try:
                    ssh.close()
                except Exception:
                    pass

    def aplicar_wireguard(self):
        """Aplica configuração do WireGuard no OPNsense."""
        try:
            requests.post(
                f"{self.opnsense_url}/api/wireguard/service/reconfigure",
                auth=self.opnsense_auth, verify=False, timeout=15
            )
        except Exception:
            pass
# ============================================================
# UI
# ============================================================
class App(ctk.CTk):
    def __init__(self, backend, db):
        super().__init__()
        self.backend = backend
        self.db = db
        self.title("Orquestrador OPNsense")
        self.geometry("1000x750")

        ctk.CTkLabel(
            self, text="Orquestrador OPNsense",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(pady=15)

        self.frame_add = ctk.CTkFrame(self)
        self.frame_add.pack(pady=10, padx=20, fill="x")

        ctk.CTkLabel(
            self.frame_add, text="Criar Cliente (VLAN + VPN)",
            font=ctk.CTkFont(size=14, weight="bold")
        ).grid(row=0, column=0, columnspan=4, padx=10, pady=(10, 5), sticky="w")

        ctk.CTkLabel(self.frame_add, text="Nome do cliente:").grid(
            row=1, column=0, padx=10, pady=8, sticky="w"
        )
        self.entry_cliente = ctk.CTkEntry(self.frame_add, width=280)
        self.entry_cliente.grid(row=1, column=1, padx=10, pady=8, sticky="w")

        ctk.CTkLabel(self.frame_add, text="Qtd peers VPN:").grid(
            row=1, column=2, padx=10, pady=8, sticky="w"
        )
        self.entry_peers = ctk.CTkEntry(self.frame_add, width=80)
        self.entry_peers.insert(0, "1")
        self.entry_peers.grid(row=1, column=3, padx=10, pady=8, sticky="w")

        self.btn_add = ctk.CTkButton(
            self.frame_add, text="Criar Cliente",
            command=self.acao_criar, height=35
        )
        self.btn_add.grid(row=1, column=4, padx=15, pady=8)

        self.frame_lista = ctk.CTkFrame(self)
        self.frame_lista.pack(pady=10, padx=20, fill="both", expand=True)

        ctk.CTkLabel(
            self.frame_lista, text="Clientes cadastrados",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(pady=(10, 5), anchor="w", padx=10)

        self.scroll_clientes = ctk.CTkScrollableFrame(self.frame_lista, height=180)
        self.scroll_clientes.pack(pady=5, padx=10, fill="both", expand=True)

        self.btn_refresh = ctk.CTkButton(
            self.frame_lista, text="Atualizar lista",
            command=self.acao_atualizar, height=30
        )
        self.btn_refresh.pack(pady=5)

        ctk.CTkLabel(
            self, text="Log",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=25)

        self.log_box = ctk.CTkTextbox(self, height=220)
        self.log_box.pack(pady=5, padx=20, fill="x")

        self.after(100, self.processar_fila)
        self.acao_atualizar()
        self.after(500, self._checar_parciais)

    def log(self, msg):
        fila_log.put(msg)

    def processar_fila(self):
        while not fila_log.empty():
            self.log_box.insert("end", fila_log.get() + "\n")
            self.log_box.see("end")
        self.after(100, self.processar_fila)

    def _checar_parciais(self):
        parciais = self.db.listar_clientes(status="parcial")
        if parciais:
            nomes = ", ".join(c["nome"] for c in parciais)
            self.log(f"[AVISO] Clientes parciais encontrados: {nomes}")
            self.log("[AVISO] Use 'Excluir' na lista pra limpar.")

    def acao_criar(self):
        nome = self.entry_cliente.get().strip()
        qtd = self.entry_peers.get().strip()

        if not nome:
            self.log("[ERRO] Informe o nome do cliente.")
            return
        if not qtd.isdigit() or not (1 <= int(qtd) <= 50):
            self.log("[ERRO] Qtd de peers deve ser entre 1 e 50.")
            return

        self.btn_add.configure(state="disabled", text="Criando...")
        threading.Thread(
            target=self._thread_criar,
            args=(nome, int(qtd)),
            daemon=True
        ).start()

    def _thread_criar(self, nome, qtd):
        try:
            self.log(f"=== Criando cliente {nome} ({qtd} peers) ===")
            r = self.backend.criar_cliente_completo(nome, qtd, self.log)
            self.log(
                f"=== OK: VLAN {r['tag']} | {r['opt_vlan']} + {r['opt_wg']} | "
                f"{r['wg_nome']} (porta {r['wg_porta']}) | {r['peers']} peers ==="
            )
            self.log(f"=== .conf salvos em: {r['pasta']} ===")
            self.entry_cliente.delete(0, "end")
            self.after(0, self.acao_atualizar)
        except Exception as e:
            self.log(f"[ERRO] {e}")
        finally:
            self.after(0, lambda: self.btn_add.configure(
                state="normal", text="Criar Cliente"
            ))

    def acao_atualizar(self):
        threading.Thread(target=self._thread_atualizar, daemon=True).start()

    def _thread_atualizar(self):
        try:
            clientes = self.db.listar_clientes()
            self.after(0, lambda: self._render_lista(clientes))
        except Exception as e:
            self.log(f"[ERRO] {e}")

    def _render_lista(self, clientes):
        for w in self.scroll_clientes.winfo_children():
            w.destroy()
        if not clientes:
            ctk.CTkLabel(self.scroll_clientes, text="Nenhum cliente cadastrado.").pack()
            return
        for c in clientes:
            row = ctk.CTkFrame(self.scroll_clientes)
            row.pack(fill="x", pady=3, padx=3)
            texto = (
                f"[{c['status'].upper()}] {c['nome']} | "
                f"VLAN {c.get('tag_vlan', '?')} | {c.get('opt_vlan', '?')} + {c.get('opt_wg', '?')} | "
                f"{c.get('nome_servidor_wg', '?')}"
            )
            ctk.CTkLabel(row, text=texto, anchor="w").pack(
                side="left", padx=10, pady=5, fill="x", expand=True
            )
            ctk.CTkButton(
                row, text="Excluir", width=80, fg_color="#a03030",
                hover_color="#802020",
                command=lambda cid=c["id"], n=c["nome"]:
                    self.confirmar_exclusao(cid, n)
            ).pack(side="right", padx=8, pady=5)

    def confirmar_exclusao(self, cliente_id, nome):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Confirmar exclusão")
        dialog.geometry("520x260")
        dialog.transient(self)
        dialog.grab_set()

        ctk.CTkLabel(
            dialog,
            text=f"Excluir o ambiente completo de {nome}?\n\n"
                 f"Vai remover TUDO que está no banco:\n"
                 f"  • Regras de firewall\n"
                 f"  • Peers WireGuard\n"
                 f"  • Servidor WireGuard\n"
                 f"  • Interfaces VLAN e WG\n"
                 f"  • VLAN\n\n"
                 f"Os .conf serão tratados depois.",
            font=ctk.CTkFont(size=12), justify="left"
        ).pack(pady=20, padx=15)

        frame = ctk.CTkFrame(dialog, fg_color="transparent")
        frame.pack(pady=10)

        def sim():
            dialog.destroy()
            threading.Thread(
                target=self._thread_excluir,
                args=(cliente_id, nome),
                daemon=True
            ).start()

        ctk.CTkButton(
            frame, text="Sim, excluir", fg_color="#a03030",
            hover_color="#802020", command=sim, width=140
        ).pack(side="left", padx=10)
        ctk.CTkButton(
            frame, text="Cancelar", command=dialog.destroy, width=140
        ).pack(side="left", padx=10)

    def _thread_excluir(self, cliente_id, nome):
        try:
            r = self.backend.excluir_cliente_por_id(cliente_id, self.log)
            self.after(0, self.acao_atualizar)
            self.after(100, lambda: self._perguntar_conf(r["nome_cliente"]))
        except Exception as e:
            self.log(f"[ERRO] {e}")

    def _perguntar_conf(self, nome_cliente):
        pasta = os.path.join(PASTA_CLIENTES, f"{nome_cliente}-vpn-peers")
        if not os.path.exists(pasta):
            return

        dialog = ctk.CTkToplevel(self)
        dialog.title("Arquivos .conf do cliente")
        dialog.geometry("520x240")
        dialog.transient(self)
        dialog.grab_set()

        ctk.CTkLabel(
            dialog,
            text=f"O que fazer com os .conf de {nome_cliente}?\n\n{pasta}",
            font=ctk.CTkFont(size=12), justify="left", wraplength=480
        ).pack(pady=25, padx=15)

        frame = ctk.CTkFrame(dialog, fg_color="transparent")
        frame.pack(pady=10)

        def apagar():
            dialog.destroy()
            try:
                shutil.rmtree(pasta)
                self.log(f"[CONF] Pasta apagada.")
            except Exception as e:
                self.log(f"[CONF] Erro: {e}")

        def arquivar():
            dialog.destroy()
            try:
                os.makedirs(PASTA_ARQUIVADOS, exist_ok=True)
                ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                destino = os.path.join(
                    PASTA_ARQUIVADOS, f"{nome_cliente}-vpn-peers_{ts}"
                )
                shutil.move(pasta, destino)
                self.log(f"[CONF] Arquivada em {destino}.")
            except Exception as e:
                self.log(f"[CONF] Erro: {e}")

        ctk.CTkButton(
            frame, text="Apagar", fg_color="#a03030",
            hover_color="#802020", command=apagar, width=140
        ).pack(side="left", padx=10)
        ctk.CTkButton(
            frame, text="Arquivar", command=arquivar, width=140
        ).pack(side="left", padx=10)
        ctk.CTkButton(
            frame, text="Cancelar", command=dialog.destroy, width=140
        ).pack(side="left", padx=10)


# ============================================================
if __name__ == "__main__":
    try:
        db = DB(DB_PATH)
        backend = Backend(db)
        app = App(backend=backend, db=db)
        app.mainloop()
    except Exception as e:
        print(f"[FATAL] {e}")