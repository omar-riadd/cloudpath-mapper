"""Interactive HTML visualization of the attack graph via pyvis.

Converts the NetworkX attack graph into an interactive HTML page with:

    - color-coded nodes by ``node_type`` (users=green, roles=orange,
      EC2 instances=red, S3 buckets=blue),
    - entity names as labels and full ARN + region in hover tooltips,
    - edge ``relation`` labels (CanAssumeRole, CanRead, ...) rendered
      on the arrows with high-contrast white fonts,
    - nodes participating in discovered attack paths outlined in
      yellow so the interesting subgraph stands out,
    - a fixed color legend in the bottom-left corner.

The generated HTML is post-processed (:func:`_post_process_html`) to
work around known pyvis issues when ``cdn_resources="remote"`` is used:
a working TomSelect build is injected so the select/filter menus are
live, and guard clauses are patched into the menu JavaScript so clean
accounts with zero edges do not freeze the dropdown UI.
"""

from __future__ import annotations

import logging
from typing import Any

import networkx as nx
from pyvis.network import Network

from cloud_path_mapper.config import HTML_REPORT_PATH

logger = logging.getLogger(__name__)

# node_type -> fill color
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

EDGE_FONT_CONFIG = {
    "color": "#ffffff",
    "size": 14,
    "strokeWidth": 2,
    "strokeColor": "#1e1e1e",
}


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
    graph: nx.DiGraph,
    highlighted_nodes: set[str] | None = None,
    output_path: Any = HTML_REPORT_PATH,
) -> Any:
    """Render the graph to an interactive, self-contained HTML file.

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
                "highlight": {
                    "border": PATH_HIGHLIGHT_BORDER,
                    "background": NODE_COLORS.get(node_type, DEFAULT_COLOR),
                },
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
            font=dict(EDGE_FONT_CONFIG),
        )

    html = net.generate_html()
    html = _post_process_html(html)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html)
    logger.info("Interactive visualization written to %s", output_path)
    return output_path


def _post_process_html(html: str) -> str:
    """Apply all runtime patches to the pyvis-generated HTML string.

    Three fixes are applied, in order:

    1. **TomSelect injection** — pyvis's remote template wires the
       select/filter menus to an outdated TomSelect build that never
       initializes; injecting the stable 2.2.2 release makes the menus
       live.
    2. **Zero-edge guards** — the ``addProperties()`` and
       ``addValues()`` menu functions iterate over ``allEdges`` when
       the user selects "edge"; on a clean account with no edges this
       freezes the UI. Guard clauses short-circuit before iteration.
    3. **Legend** — a fixed color-key overlay is injected since pyvis
       has no native legend support.

    Args:
        html: The raw HTML string produced by ``Network.generate_html``.

    Returns:
        The fully patched HTML string.
    """
    html = _inject_tom_select(html)
    html = _inject_zero_edge_guards(html)
    html = _inject_legend(html)
    return html


def _inject_tom_select(html: str) -> str:
    """Inject a working TomSelect CSS/JS pair into ``<head>``.

    Args:
        html: Raw pyvis HTML string.

    Returns:
        Patched HTML string.
    """
    if TOM_SELECT_JS in html:
        return html
    tags = (
        f'<link href="{TOM_SELECT_CSS}" rel="stylesheet">\n'
        f'<script src="{TOM_SELECT_JS}"></script>\n'
    )
    return html.replace("</head>", tags + "</head>", 1)


def _inject_zero_edge_guards(html: str) -> str:
    """Patch menu JavaScript to tolerate graphs with zero edges.

    Uses targeted ``str.replace`` calls against the exact function
    bodies pyvis emits for ``addProperties()`` and ``addValues()``.
    When the user picks "edge" in the filter menus, the injected guard
    returns immediately instead of iterating an empty ``allEdges``
    object, which otherwise leaves the dropdown unresponsive.

    Idempotent: re-running on already-patched content is a no-op.

    Args:
        html: Raw pyvis HTML string.

    Returns:
        Patched HTML string.
    """
    guard = "if (!allEdges || Object.keys(allEdges).length === 0) { return; }"

    add_values_marker = "else if (filter['item'] === 'edge') {"
    if add_values_marker in html and guard not in html[html.index(add_values_marker):][:200]:
        html = html.replace(
            add_values_marker,
            f"{add_values_marker} {guard}",
        )

    add_properties_marker = "if (arguments[0] === 'edge') {"
    if (
        add_properties_marker in html
        and guard not in html[html.index(add_properties_marker):][:200]
    ):
        html = html.replace(
            add_properties_marker,
            f"{add_properties_marker} {guard}",
        )

    return html


def _inject_legend(html: str) -> str:
    """Prepend a fixed bottom-left color legend after ``<body>``.

    Args:
        html: Raw pyvis HTML string.

    Returns:
        Patched HTML string.
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
        "</div>\n"
    )
    marker = "<body>"
    return html.replace(marker, marker + "\n" + legend_html, 1)
