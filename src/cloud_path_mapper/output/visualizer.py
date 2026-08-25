"""Interactive HTML visualization of the attack graph via pyvis.

Converts the NetworkX attack graph into an interactive HTML page with:

    - color-coded nodes by ``node_type`` (users=green, roles=orange,
      EC2 instances=red, S3 buckets=blue),
    - entity names as labels and full ARN + region in hover tooltips,
    - edge ``relation`` labels (CanAssumeRole, CanRead, ...) rendered
      on the arrows,
    - nodes participating in discovered attack paths outlined in
      yellow so the interesting subgraph stands out.
"""

from __future__ import annotations

import logging
from typing import Any

from pyvis.network import Network

from cloud_path_mapper.config import HTML_REPORT_PATH

logger = logging.getLogger(__name__)

# node_type -> (fill color, legend label)
NODE_COLORS: dict[str, str] = {
    "user": "#2ecc71",        # green
    "role": "#e67e22",        # orange
    "ec2_instance": "#e74c3c",  # red
    "s3_bucket": "#3498db",   # blue
}

DEFAULT_COLOR = "#95a5a6"
PATH_HIGHLIGHT_BORDER = "#f1c40f"

# With cdn_resources='remote', pyvis references an outdated TomSelect
# build that fails to initialize, leaving its filter/select dropdowns
# dead. Injecting the current stable release explicitly fixes them.
TOM_SELECT_CSS = "https://cdn.jsdelivr.net/npm/tom-select@2.2.2/dist/css/tom-select.css"
TOM_SELECT_JS = "https://cdn.jsdelivr.net/npm/tom-select@2.2.2/dist/js/tom-select.complete.min.js"


def _node_title(attrs: dict) -> str:
    """Build the hover tooltip for a node.

    Args:
        attrs: Node attribute dict from the NetworkX graph.

    Returns:
        HTML string with ARN and region (when applicable).
    """
    lines = [f"<b>{attrs.get('arn', 'unknown')}</b>"]
    if attrs.get("region"):
        lines.append(f"region: {attrs['region']}")
    if attrs.get("node_type") == "s3_bucket":
        if attrs.get("publicly_exposed"):
            lines.append("<b>PUBLICLY EXPOSED</b>")
        pab = "configured" if attrs.get("pab_configured") else "NOT configured"
        lines.append(f"public access block: {pab}")
    return "<br>".join(lines)


def build_visualization(
    graph: Any,
    highlighted_nodes: set[str] | None = None,
    output_path: Any = HTML_REPORT_PATH,
) -> Any:
    """Render the graph to an interactive pyvis HTML file.

    Args:
        graph: The :class:`networkx.DiGraph` from the analysis layer.
        highlighted_nodes: Optional set of ARNs on discovered attack
            paths; these get a thick yellow border.
        output_path: Destination HTML path.

    Returns:
        The path written to.
    """
    highlighted_nodes = highlighted_nodes or set()

    net = Network(
        height="900px",
        width="100%",
        directed=True,
        bgcolor="#1e1e1e",
        font_color="#ffffff",
        select_menu=True,
        filter_menu=True,
        # 'local' (the pyvis default) writes library references like
        # lib/bindings/utils.js relative to the HTML file; browsers
        # block those loads over file:/// so the canvas renders blank.
        # 'remote' pins vis-network to a CDN URL instead.
        cdn_resources="remote",
    )
    net.barnes_hut(gravity=-8000, central_gravity=0.3, spring_length=150)

    for node, attrs in graph.nodes(data=True):
        node_type = str(attrs.get("node_type", "unknown"))
        on_path = node in highlighted_nodes
        net.add_node(
            node,
            label=str(attrs.get("name", node)),
            title=_node_title(attrs),
            color={
                "border": PATH_HIGHLIGHT_BORDER if on_path else NODE_COLORS.get(node_type, DEFAULT_COLOR),
                "background": NODE_COLORS.get(node_type, DEFAULT_COLOR),
                "highlight": {"border": PATH_HIGHLIGHT_BORDER, "background": NODE_COLORS.get(node_type, DEFAULT_COLOR)},
            },
            borderWidth=4 if on_path else 1,
            shape="dot",
            size=18 if on_path else 12,
        )

    for source, target, edge_attrs in graph.edges(data=True):
        relation = str(edge_attrs.get("relation", ""))
        net.add_edge(
            source,
            target,
            label=relation,
            title=relation,
            arrows="to",
            font={
                "color": "#ffffff",
                "size": 14,
                "strokeWidth": 2,
                "strokeColor": "#1e1e1e",
            },
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    net.save_graph(str(output_path))
    _inject_tom_select(output_path)
    logger.info("Interactive visualization written to %s", output_path)
    return output_path


def _inject_tom_select(output_path: Any) -> Any:
    """Patch the saved HTML with a working TomSelect build.

    pyvis's remote-CDN template wires its filter/select dropdowns to
    TomSelect but references a release-candidate build that never
    initializes, so the menus render but do not respond. This injects
    the stable 2.2.2 CSS + JS from jsdelivr into ``<head>``; the
    later-loaded stable version takes over the same bindings.

    Args:
        output_path: The HTML file produced by :func:`build_visualization`.

    Returns:
        The path written to.
    """
    tags = (
        f'<link href="{TOM_SELECT_CSS}" rel="stylesheet">\n'
        f'<script src="{TOM_SELECT_JS}"></script>\n'
    )
    content = output_path.read_text()
    if TOM_SELECT_JS in content:
        return output_path
    patched = content.replace("</head>", tags + "</head>", 1)
    output_path.write_text(patched)
    return output_path


def inject_legend(output_path: Any = HTML_REPORT_PATH) -> Any:
    """Prepend a static color legend to the generated HTML report.

    pyvis does not render legends natively; this injects a small fixed
    overlay div into the saved file.

    Args:
        output_path: The HTML file produced by :func:`build_visualization`.

    Returns:
        The path written to.
    """
    legend_items = "".join(
        f'<span style="margin-right:16px;"><span style="display:inline-block;width:12px;height:12px;'
        f'border-radius:50%;background:{color};margin-right:5px;"></span>{node_type}</span>'
        for node_type, color in NODE_COLORS.items()
    )
    legend_html = (
        '<div style="position:fixed;bottom:20px;left:20px;z-index:999;background:#1e1e1ecc;'
        f'padding:10px 14px;border-radius:6px;color:white;font-family:sans-serif;">'
        f'<b>Node types:</b> {legend_items}'
        f'<span style="display:inline-block;width:12px;height:2px;background:#fff;margin-right:5px;'
        'border-bottom:2px dashed #fff;"></span>'
        "</div>\n"
    )
    content = output_path.read_text()
    marker = "<body>"
    patched = content.replace(marker, marker + "\n" + legend_html, 1)
    output_path.write_text(patched)
    return output_path
