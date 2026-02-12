"""Generate an interactive HTML visualisation of the infrastructure graph."""

from __future__ import annotations

from pathlib import Path

from pyvis.network import Network as PyvisNet

from .loader import build_graph

# Colour palette per device type
DEVICE_COLORS: dict[str, str] = {
    "router": "#e74c3c",    # red
    "switch": "#9b59b6",    # purple
    "gateway": "#3498db",   # blue
    "sensor": "#2ecc71",    # green
    "compute": "#e67e22",   # orange
    "camera": "#f39c12",    # amber
    "ap": "#1abc9c",        # teal
    "external": "#95a5a6",  # grey
}

# Edge dash patterns per link type
EDGE_STYLES: dict[str, dict] = {
    "ethernet": {"color": "#7f8c8d", "dashes": False, "width": 2},
    "lorawan": {"color": "#27ae60", "dashes": [10, 10], "width": 1.5},
    "zigbee": {"color": "#2980b9", "dashes": [5, 5], "width": 1.5},
    "mqtt": {"color": "#8e44ad", "dashes": [2, 6], "width": 1.5},
    "wan": {"color": "#e74c3c", "dashes": [15, 5], "width": 2},
}


def generate_html(output_path: str | Path | None = None) -> Path:
    """Build the pyvis network and write an HTML file.

    Returns the path to the generated file.
    """
    backend = build_graph()
    graph_data = backend.to_dict()

    if output_path is None:
        output_path = (
            Path(__file__).resolve().parent.parent / "output" / "nato_lab.html"
        )
    else:
        output_path = Path(output_path)

    net = PyvisNet(
        height="900px",
        width="100%",
        directed=True,
        notebook=False,
    )
    net.barnes_hut(gravity=-3000, central_gravity=0.3, spring_length=150)

    # --- Nodes ---
    for node in graph_data["nodes"]:
        nid = node["id"]
        ntype = node.get("type", "external")
        color = DEVICE_COLORS.get(ntype, "#bdc3c7")
        ip = node.get("ip") or ""
        role = node.get("role") or ""
        label = node.get("name", nid)
        title = f"<b>{label}</b><br>Type: {ntype}<br>IP: {ip}<br>Role: {role}"

        if ip:
            label += f"\n{ip}"

        net.add_node(
            nid,
            label=label,
            title=title,
            color=color,
            shape="box" if ntype in ("router", "switch") else "dot",
            size=25 if ntype in ("router", "switch", "gateway") else 18,
        )

    # --- Edges ---
    for edge in graph_data["edges"]:
        etype = edge.get("type", "ethernet")
        style = EDGE_STYLES.get(etype, EDGE_STYLES["ethernet"])
        desc = edge.get("description", "")
        title = f"{etype}" + (f" — {desc}" if desc else "")

        net.add_edge(
            edge["source"],
            edge["target"],
            title=title,
            color=style["color"],
            width=style["width"],
            dashes=style["dashes"],
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    net.write_html(str(output_path))
    print(f"Visualisation written to {output_path}")
    return output_path


if __name__ == "__main__":
    generate_html()
