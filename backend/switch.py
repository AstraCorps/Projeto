"""
Módulo de conexão Netmiko para o Cisco SG220-26 (Small Business Layer 2 Smart Switch)

⚠️  IMPORTANTE — diferenças do SG220 vs IOS padrão:
    • device_type = 'cisco_s300'  (NÃO 'cisco_ios')
    • Nomes de interface: GigabitEthernet1 ... GigabitEthernet26
      (abreviação aceita: gi1, gi26)
    • Portas 25–26 são SFP compartilhadas (combo GE25/GE26)
    • Comando para config de porta: interface GigabitEthernet X
    • Sem suporte a Telnet habilitado por padrão — use SSH v2
"""

import re
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from typing import Optional

DEVICE_TYPE = "cisco_s300"
TOTAL_PORTS = 26
SFP_PORTS   = {25, 26}

# ──────────────────────────────────────────────────────────────────
# Parsers auxiliares
# ──────────────────────────────────────────────────────────────────

def _parse_interfaces_status(raw: str) -> list[dict]:
    """
    Parseia a saída de 'show interfaces status'.

    Exemplo de linha:
      gi1      connected    1      a-full  a-1G    10/100/1000BaseTX
      gi25     notconnect   1      auto    auto    Not Present
    """
    ports = []
    # Regex compatível com o formato do SG220
    pattern = re.compile(
        r"^(gi\d+|te\d+)\s+"
        r"(\S+)\s+"          # status: connected / notconnect / disabled
        r"(\S+)\s+"          # vlan
        r"(\S+)\s+"          # duplex
        r"(\S+)",            # speed
        re.MULTILINE | re.IGNORECASE,
    )
    for m in pattern.finditer(raw):
        iface, status, vlan, duplex, speed = m.groups()
        port_num = int(re.search(r"\d+", iface).group())
        ports.append({
            "id":          port_num,
            "interface":   f"GigabitEthernet{port_num}",
            "type":        "SFP" if port_num in SFP_PORTS else "RJ-45",
            "status":      "up" if status.lower() == "connected" else "down",
            "raw_status":  status,
            "vlan":        vlan,
            "duplex":      duplex,
            "speed":       speed,
        })
    # Garante que todas as 26 portas apareçam mesmo sem link
    present_ids = {p["id"] for p in ports}
    for i in range(1, TOTAL_PORTS + 1):
        if i not in present_ids:
            ports.append({
                "id":         i,
                "interface":  f"GigabitEthernet{i}",
                "type":       "SFP" if i in SFP_PORTS else "RJ-45",
                "status":     "down",
                "raw_status": "notconnect",
                "vlan":       "1",
                "duplex":     "--",
                "speed":      "--",
            })
    return sorted(ports, key=lambda p: p["id"])


def _parse_port_detail(raw: str, port_id: int) -> dict:
    """
    Parseia 'show interfaces GigabitEthernetX counters' +
            'show interfaces GigabitEthernetX'
    """
    def extract(pattern, text, default="--"):
        m = re.search(pattern, text, re.IGNORECASE)
        return m.group(1).strip() if m else default

    return {
        "id":          port_id,
        "interface":   f"GigabitEthernet{port_id}",
        "type":        "SFP" if port_id in SFP_PORTS else "RJ-45",
        "description": extract(r"Description:\s*(.+)", raw),
        "status":      extract(r"GigabitEthernet\d+\s+is\s+(\S+)", raw),
        "speed":       extract(r"(\d+\s*Mb/s)", raw),
        "duplex":      extract(r"(Full|Half)-duplex", raw),
        "rx_bytes":    extract(r"Input\s+(\d+)\s+bytes", raw, "0"),
        "tx_bytes":    extract(r"Output\s+(\d+)\s+bytes", raw, "0"),
        "rx_errors":   extract(r"Input errors\s+(\d+)", raw, "0"),
        "tx_errors":   extract(r"Output errors\s+(\d+)", raw, "0"),
        "raw":         raw,
    }


def _parse_mac_table(raw: str) -> list[dict]:
    """
    Parseia 'show mac address-table'.
    Formato: VLAN  MAC Address         Type       Ports
    """
    entries = []
    pattern = re.compile(
        r"(\d+)\s+([\da-f:]+)\s+(static|dynamic)\s+(\S+)",
        re.IGNORECASE | re.MULTILINE,
    )
    for m in pattern.finditer(raw):
        vlan, mac, mtype, port = m.groups()
        port_num = int(re.search(r"\d+", port).group()) if re.search(r"\d+", port) else 0
        entries.append({
            "vlan": vlan, "mac": mac.lower(),
            "type": mtype, "port": port, "port_id": port_num,
        })
    return entries


def _parse_vlans(raw: str) -> list[dict]:
    """Parseia 'show vlan'."""
    vlans = []
    pattern = re.compile(r"^(\d+)\s+(\S+)\s+(active|suspend)", re.MULTILINE | re.IGNORECASE)
    for m in pattern.finditer(raw):
        vid, name, status = m.groups()
        vlans.append({"id": vid, "name": name, "status": status})
    return vlans


# ──────────────────────────────────────────────────────────────────
# Classe principal
# ──────────────────────────────────────────────────────────────────

class SG220Connection:
    """
    Context manager para conexão SSH com o Cisco SG220-26.

    Uso:
        with SG220Connection("192.168.1.1", "admin", "admin") as sw:
            ports = sw.get_interfaces_status()
    """

    def __init__(self, host: str, username: str, password: str, port: int = 22):
        self._device = {
            "device_type":       DEVICE_TYPE,
            "host":              host,
            "username":          username,
            "password":          password,
            "port":              port,
            "timeout":           15,
            "session_timeout":   30,
            "banner_timeout":    10,
        }
        self._conn = None

    # ── Context manager ──────────────────────────────────────────

    def __enter__(self):
        try:
            self._conn = ConnectHandler(**self._device)
        except NetmikoAuthenticationException:
            raise ValueError(f"Falha de autenticação em {self._device['host']}")
        except NetmikoTimeoutException:
            raise TimeoutError(f"Timeout ao conectar em {self._device['host']}")
        return self

    def __exit__(self, *_):
        if self._conn:
            self._conn.disconnect()

    # ── Informações do sistema ────────────────────────────────────

    def get_system_info(self) -> dict:
        """Retorna hostname, versão de firmware e uptime."""
        raw = self._conn.send_command("show version")
        return {
            "hostname": self._conn.find_prompt().replace("#", "").strip(),
            "firmware": re.search(r"Version\s+([\d.()a-zA-Z]+)", raw, re.I).group(1) if re.search(r"Version", raw, re.I) else "--",
            "uptime":   re.search(r"uptime is (.+)", raw, re.I).group(1).strip() if re.search(r"uptime is", raw, re.I) else "--",
            "model":    "SG220-26",
        }

    # ── Interfaces ────────────────────────────────────────────────

    def get_interfaces_status(self) -> list[dict]:
        """Status de todas as 26 portas."""
        raw = self._conn.send_command("show interfaces status")
        return _parse_interfaces_status(raw)

    def get_port_detail(self, port_id: int) -> dict:
        """Detalhes e contadores de uma porta."""
        iface = f"GigabitEthernet{port_id}"
        raw_if  = self._conn.send_command(f"show interfaces {iface}")
        raw_cnt = self._conn.send_command(f"show interfaces {iface} counters")
        return _parse_port_detail(raw_if + "\n" + raw_cnt, port_id)

    # ── MAC / VLAN ────────────────────────────────────────────────

    def get_mac_table(self) -> list[dict]:
        raw = self._conn.send_command("show mac address-table")
        return _parse_mac_table(raw)

    def get_vlans(self) -> list[dict]:
        raw = self._conn.send_command("show vlan")
        return _parse_vlans(raw)

    # ── Backup ───────────────────────────────────────────────────

    def get_running_config(self) -> str:
        return self._conn.send_command("show running-config", read_timeout=30)

    # ── Configuração ─────────────────────────────────────────────

    def configure_port(
        self,
        port_id: int,
        description: Optional[str] = None,
        shutdown: Optional[bool] = None,
    ) -> str:
        """
        Entra no modo de configuração e aplica alterações na porta.
        shutdown=True  → desativa a porta
        shutdown=False → reativa a porta
        """
        iface = f"GigabitEthernet{port_id}"
        cmds = [f"interface {iface}"]
        if description is not None:
            cmds.append(f"description {description}")
        if shutdown is True:
            cmds.append("shutdown")
        elif shutdown is False:
            cmds.append("no shutdown")
        cmds.append("exit")

        output = self._conn.send_config_set(cmds)
        # Salva configuração na NVRAM
        self._conn.save_config()
        return output
