import requests
import json
import base64
import uuid
import ipaddress
from nacl.public import PrivateKey
from typing import Optional, Tuple, Dict, Any, List
import urllib.parse
class XUIService:
    """
    Client for interacting with the 3X-UI panel API.
    """

    def __init__(self, host: str, port: int, web_base_path: str, username: str, password: str):
        self.host = host
        self.port = port
        self.web_base_path = web_base_path  # include leading slash, e.g. "/panel"
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.base_url = f"http://{self.host}:{self.port}{self.web_base_path}"

    def login(self) -> Dict[str, Any]:
        url = f"{self.base_url}/login"
        data = {"username": self.username, "password": self.password}
        resp = self.session.post(url, data=data)
        resp.raise_for_status()
        result = resp.json()
        if not result.get("success"):
            raise Exception(f"Login failed: {result.get('msg')}")
        return result

    def list_inbounds(self) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/panel/api/inbounds/list"
        resp = self.session.get(url)
        resp.raise_for_status()
        return resp.json().get("obj", [])

    def get_least_clients_inbound(self, protocol: str = "vless") -> Dict[str, Any]:
        inbounds = self.list_inbounds()
        filtered = [i for i in inbounds if i.get("protocol") == protocol]
        if not filtered:
            raise Exception(f"No inbounds with protocol '{protocol}'")
        return min(filtered, key=lambda i: len(i.get("clientStats", [])))

    def _generate_wg_keys(self) -> Tuple[str, str]:
        priv = PrivateKey.generate()
        pub = priv.public_key
        priv_b64 = base64.b64encode(priv.encode()).decode()
        pub_b64  = base64.b64encode(pub.encode()).decode()
        return priv_b64, pub_b64

    def pick_new_ip(self, settings_json: str, network_cidr: str = "10.0.0.0/24") -> str:
        settings = json.loads(settings_json)
        peers = settings.get("peers", [])
        used_ips = {
            ipaddress.IPv4Address(ip.split("/")[0])
            for peer in peers for ip in peer.get("allowedIPs", [])
        }
        network = ipaddress.IPv4Network(network_cidr)
        for host in network.hosts():
            if host not in used_ips:
                return f"{host.compressed}/32"
        raise Exception("IP pool exhausted")

    def add_wireguard_peer(self, inbound_id: int, name: str, keepalive: int = 25) -> Dict[str, Any]:
        # 1. Получаем существующий inbound
        orig = next((i for i in self.list_inbounds() if i["id"] == inbound_id), None)
        if not orig:
            raise Exception(f"Inbound {inbound_id} not found")

        # 2. Сгенерировать новый IP и ключи
        settings_json = orig["settings"]
        new_ip = self.pick_new_ip(settings_json)
        priv_b64, pub_b64 = self._generate_wg_keys()

        # 3. Добавляем новый peer в settings
        settings = json.loads(settings_json)
        new_peer = {
            "privateKey": priv_b64,
            "publicKey":  pub_b64,
            "allowedIPs": [new_ip],
            "keepAlive":  keepalive,
            "name":       name,
        }
        settings.setdefault("peers", []).append(new_peer)

        # 4. Формируем payload для обновления
        payload = {k: orig[k] for k in orig if k not in ("id", "clientStats")}
        payload["settings"] = json.dumps(settings)

        # 5. Отправляем запрос на обновление
        url = f"{self.base_url}/panel/api/inbounds/update/{inbound_id}"
        resp = self.session.post(url, json=payload)
        resp.raise_for_status()
        result = resp.json()
        if not result.get("success"):
            raise Exception(f"Update Inbound failed: {result.get('msg')}")

        return {"peer": new_peer, "result": result}

    def format_wg_config(self, data: dict, dns: str = "1.1.1.1, 1.0.0.1") -> str:
        """
        data: {
          'peer': {
            'privateKey': str,
            'publicKey': str,
            'allowedIPs': [str],
            'keepAlive': int,
            'name': str,  # опционально
          },
          'result': {
            'obj': {
              'port': int,
              'protocol': 'wireguard',
              'settings': ...,
              # другие поля...
            }
          }
        }
        """
        peer = data["peer"]
        inbound = data["result"]["obj"]

        # Interface section (это мы — клиент)
        iface = [
            "[Interface]",
            f"PrivateKey = {peer['privateKey']}",
            f"Address = {peer['allowedIPs'][0]}",
            f"DNS = {dns}",
            # берём MTU из settings JSON:
        ]
        # вытаскиваем MTU из JSON-строки inbound["settings"]
        settings = json.loads(inbound["settings"])
        mtu = settings.get("mtu")
        if mtu:
            iface.append(f"MTU = {mtu}")

        # Peer section (это сервер)
        endpoint = f"{data['service_host']}:{inbound['port']}" if 'service_host' in data else f"{inbound.get('listen', '')}:{inbound['port']}"
        peer_section = [
            "",
            "[Peer]",
            f"PublicKey = {peer['publicKey']}",
            "AllowedIPs = 0.0.0.0/0, ::/0",
            f"Endpoint = {endpoint}",
            f"PersistentKeepalive = {peer.get('keepAlive', 0)}",
        ]

        return "\n".join(iface + peer_section)

    def find_client(self, email: str) -> Optional[Tuple[int, Dict[str, Any]]]:
        """
        Перебирает все inbounds, ищет в clientStats запись с заданным email.
        Возвращает кортеж (inbound_id, client_stats_dict) или None, если не найдено.
        """
        for inbound in self.list_inbounds():
            for client in inbound.get("clientStats", []):
                if client.get("email") == email:
                    return inbound["id"], client
        return None

    def add_client(self, inbound_id: int, email: str) -> (dict, dict):
        """
        Add a new client to the specified inbound.
        Returns a tuple of (client_info, api_response).
        client_info contains the generated id and subId to connect.
        Raise exception if API reports failure.
        """
        # Generate client credentials
        client = {
            "id": str(uuid.uuid4()),
            "flow": "",
            "email": email,
            "limitIp": 0,
            "totalGB": 0,
            "expiryTime": 0,
            "enable": True,
            "tgId": "",
            "subId": uuid.uuid4().hex,
            "reset": 0
        }
        settings_obj = {"clients": [client]}
        payload = {"id": inbound_id, "settings": json.dumps(settings_obj)}
        url = f"{self.base_url}/panel/api/inbounds/addClient"
        try:
            resp = self.session.post(url, json=payload)
            resp.raise_for_status()
            result = resp.json()
            if not result.get("success"):
                raise Exception(f"Add client failed: {result.get('msg')}")
            return client, result
        except Exception as e:
            existing= self.get_client_config_by_email(email, protocol='vless')
            return existing



    def get_client_traffic(self, email: str) -> dict:
        """
        Retrieve traffic stats for a client by email.
        Returns the API response object.
        """
        url = f"{self.base_url}/panel/api/inbounds/getClientTraffics/{email}"
        resp = self.session.get(url)
        resp.raise_for_status()
        return resp.json()

    def get_client_traffic_by_id(self, client_uuid: str) -> dict:
        """
        Retrieve traffic stats for a client by UUID.
        Returns the API response object.
        """
        url = f"{self.base_url}/panel/api/inbounds/getClientTrafficsById/{client_uuid}"
        resp = self.session.get(url)
        resp.raise_for_status()
        return resp.json()

    def format_vless_url(self, client_info, inbound, host, port):
        """
        Формирует VLESS-ссылку на основе данных клиента и inbound.

        :param client_tuple: кортеж (client_info: dict, api_response: dict)
        :param inbound: dict с данными inbound (из list_inbounds или API)
        :param host: адрес сервера
        :param port: порт inbound
        :return: строка VLESS URL
        """

        # Парсим streamSettings JSON
        stream = json.loads(inbound["streamSettings"])
        network = stream.get("network", "tcp")
        security = stream.get("security", "none")

        # Внутри реалити-настроек
        reality = stream.get("realitySettings", {})
        pbk = reality.get("publicKey", "")
        fp = reality.get("fingerprint", "")
        sni = reality.get("serverNames", [""])[0]
        # Берём первый shortId
        sid = reality.get("shortIds", [""])[0]
        # SpiderX (путь) нужно URL-закодировать
        spx = urllib.parse.quote(reality.get("settings", {}).get("spiderX", ""))

        # Формируем параметры
        params = {
            "type": network,
            "security": security,
            "pbk": pbk,
            "fp": fp,
            "sni": sni,
            "sid": sid,
            "spx": spx
        }
        query = "&".join(f"{k}={v}" for k, v in params.items())

        # Якорь — по email или по remark
        remark = client_info['email']

        # Составляем итоговую ссылку
        return f"vless://{client_info['id']}@{host}:{port}?{query}#{remark}"

    def get_inbound(self, inbound_id: int) -> Dict[str, Any]:
        """GET /panel/api/inbounds/get/{inboundId}"""
        url = f"{self.base_url}/panel/api/inbounds/get/{inbound_id}"
        resp = self.session.get(url)
        resp.raise_for_status()
        result = resp.json()
        if not result.get("success"):
            raise Exception(f"Get inbound failed: {result.get('msg')}")
        return result["obj"]

    def find_client_in_inbound(self, inbound: Dict[str, Any], email: str) -> Dict[str, Any]:
        """
        Ищет клиента по email:
        - для VLESS: в JSON-поле inbound['settings'] -> clients
        - для WireGuard: в JSON-поле inbound['settings'] -> peers
        """
        proto = inbound.get("protocol")
        settings = json.loads(inbound["settings"])
        key = "clients" if proto in ("vless", "vmess") else "peers"
        for entry in settings.get(key, []):
            if entry.get("email") == email or entry.get("name") == email:
                return entry
        raise Exception(f"Client with email '{email}' not found in inbound {inbound['id']}")

    def get_client_config_by_email(
            self,
            email: str,
            protocol: str,
    ) -> dict[str, Any]:
        """
        Ищет среди всех inbounds тот, где protocol совпадает и есть клиент с этим email,
        затем возвращает (inbound_id, конфиг_текст).
        """
        for inbound in self.list_inbounds():
            if inbound.get("protocol") != protocol:
                continue
            # Получаем полный inbound для settings
            full = self.get_inbound(inbound["id"])
            try:
                entry = self.find_client_in_inbound(full, email)
                return entry
            except Exception:
                continue