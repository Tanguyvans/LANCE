"""Observe graph context replacement in memory; never load a real laboratory.

Run: PYTHONDONTWRITEBYTECODE=1 python -m scripts.analysis.graph_context_probe
The audit hook is an extra check, not an exhaustive native-code sandbox.
"""
import json
import sys
from unittest.mock import patch


def main() -> None:
    blocked = []

    def guard(event, args):
        if event in {"socket.connect", "socket.connect_ex", "subprocess.Popen"}:
            blocked.append(event)
            raise AssertionError(event)
        if event == "open":
            flags = args[2]
            if isinstance(flags, int) and flags & (1 | 2 | 64 | 512 | 1024):
                blocked.append(event)
                raise AssertionError("write open")

    sys.addaudithook(guard)
    from src.agent.tools import graph_tools as graph

    graph.load_discovery_context("192.0.2.0/24")
    first = json.loads(graph.get_network_topology())
    graph.load_discovery_context("198.51.100.0/24")
    second = json.loads(graph.get_network_topology())
    assert first["target_network"] == "192.0.2.0/24"
    assert second["target_network"] == "198.51.100.0/24"
    assert graph.current_graph_context().discovery_mode["target_network"] != "192.0.2.0/24"
    graph._reset_graph_context()
    with patch.object(graph, "load_lab_context") as fallback:
        graph._ensure_loaded()
        assert fallback.call_count == 1
    print(json.dumps({"context_replaced": True,
                      "unprepared_read_requests_lab_load": True,
                      "external_or_file_writes_blocked": blocked}))


if __name__ == "__main__":
    main()
