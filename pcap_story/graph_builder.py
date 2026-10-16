"""Build an aggregated graph with links back to complete activity evidence."""

from .models import stable_id


def build_graph(activities, flows, config):
    nodes, edges = {}, {}
    flow_index = {flow.id: flow for flow in flows}
    initiators = {flow.source_ip for flow in flows}
    initiators.update(activity["source_ip"] for activity in activities)

    def node(kind, label, **data):
        identity = stable_id("ip" if kind in {"host", "server"} else kind, label)
        if identity not in nodes:
            nodes[identity] = {"id": identity, "type": kind, "label": label, "data": data}
        return identity

    def ip_node(address):
        return node("host" if address in initiators else "server", address, ip=address)

    def edge(source, target, kind, label, activity_id):
        identity = stable_id("edge", source, target, kind)
        item = edges.setdefault(identity, {
            "id": identity, "source": source, "target": target,
            "type": kind, "label": label, "data": {"activity_ids": []},
        })
        if activity_id not in item["data"]["activity_ids"]:
            item["data"]["activity_ids"].append(activity_id)

    for activity in activities[:config.max_graph_activities]:
        aid = activity["id"]
        host = ip_node(activity["source_ip"])
        nodes[aid] = {"id": aid, "type": "activity", "label": activity["title"],
                      "data": {"activity_id": aid, "confidence": activity["confidence"],
                               "start_time": activity["start_time"], "end_time": activity["end_time"]}}
        edge(host, aid, "RELATED_TO", "Observed activity", aid)
        for flow_id in activity["flow_ids"]:
            flow = flow_index[flow_id]
            server = ip_node(flow.destination_ip)
            edge(host, server, "CONNECTED_TO", "Connection", aid)
            edge(server, aid, "RELATED_TO", "Participates in activity", aid)
        for domain in activity["domains"]:
            domain_id = node("domain", domain)
            edge(domain_id, aid, "RELATED_TO", "Activity evidence", aid)
        for event in activity["evidence"]:
            domain = event["data"].get("domain")
            if not domain:
                continue
            domain_id = node("domain", domain)
            kind = {"DNS_QUERY": "DNS_QUERY", "TLS_CONNECTION": "TLS", "HTTP_REQUEST": "HTTP"}.get(event["type"])
            if kind:
                edge(host, domain_id, kind, {"DNS_QUERY": "DNS query", "TLS": "TLS server name", "HTTP": "HTTP Host"}[kind], aid)
            if kind in {"TLS", "HTTP"}:
                edge(domain_id, ip_node(event["destination"]["ip"]), "RELATED_TO", "Observed service endpoint", aid)
    return list(nodes.values()), list(edges.values())
