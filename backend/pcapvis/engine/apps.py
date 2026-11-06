"""Application-layer notes per flow (HTTP, MQTT, CoAP) and host identity hints."""

from collections import defaultdict

from pcapvis.engine.packet import Packet

MAX_NOTES = 25


class FlowNotes:
    """Small capped lists of interesting strings per flow, keyed by note type."""

    def __init__(self):
        self.notes: dict[tuple, dict[str, list[str]]] = defaultdict(dict)  # flow key → note type → values
        self.request_uris: list[str] = []  # HTTP request URIs (links extracted files to their URL)

    def add(self, flow_key: tuple, key: str, value: str | None) -> None:
        if not value:
            return
        lst = self.notes[flow_key].setdefault(key, [])
        if value not in lst and len(lst) < MAX_NOTES:
            lst.append(value[:300])

    def merge(self, other: "FlowNotes") -> None:
        """Partitions never share a flow, so notes combine without conflicts."""
        self.notes.update(other.notes)
        room = 100_000 - len(self.request_uris)
        self.request_uris.extend(other.request_uris[: max(room, 0)])

    def extract(self, p: Packet, flow_id: tuple) -> dict[str, str]:
        """Record notes; return identity facts for the *sending* host."""
        L = p.layers
        ident: dict[str, str] = {}
        if "http_request_method" in L:
            host = (L.get("http_host") or [""])[0]
            uri = (L.get("http_request_uri") or [""])[0]
            self.add(flow_id, "http_requests", f"{L['http_request_method'][0]} {host}{uri}")
            self.add(flow_id, "user_agents", (L.get("http_user_agent") or [None])[0])
            if len(self.request_uris) < 100_000:
                self.request_uris.append(f"{host}{uri}")
        if "http_server" in L:
            self.add(flow_id, "http_servers", L["http_server"][0])
            ident["http_server"] = L["http_server"][0][:120]
        if "http_response_code" in L:
            self.add(flow_id, "http_status", L["http_response_code"][0])
        if "mqtt_topic" in L:
            for t in L["mqtt_topic"]:
                self.add(flow_id, "mqtt_topics", t)
        if "mqtt_clientid" in L:
            self.add(flow_id, "mqtt_client_ids", L["mqtt_clientid"][0])
        if "coap_opt_uri_path" in L:
            self.add(flow_id, "coap_paths", "/" + "/".join(L["coap_opt_uri_path"]))
        return ident
