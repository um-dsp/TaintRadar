import re

import pandas as pd

SANITIZED_COLOR = "#b6d7a8ff"
UNSANITIZED_COLOR = "#ea9999ff"

# Node lines produced by Joern's dotAst, e.g. "30064771076" [label = <htmlentities, 3<BR/>htmlentities($name)> ]
NODE_PATTERN = re.compile(r'^"(\d+)" \[label = <(.*)> \]$')


def simplify_label(label):
    """Drop the code (last line) and the line number from a node label."""
    lines = label.split("<BR/>")
    if len(lines) > 1:
        lines = lines[:-1]
    lines[0] = re.sub(r", \d+$", "", lines[0])
    return "<BR/>".join(lines)


tags = pd.read_csv("output/graph/tags.txt", header=None, index_col=0)[1].to_dict()

with open("output/graph/ast_unsan.dot", "r") as graph, open("output/graph/ast_unsan_colored.dot", "w") as new_graph:
    for line in graph:
        line = line.rstrip()

        if line.startswith("node ["):
            new_graph.write('node [shape="ellipse"];\n')
            continue

        match = NODE_PATTERN.match(line)
        if match is None:  # graph header, edges and closing brace
            new_graph.write(line + "\n")
            continue

        node_id, label = match.groups()
        attributes = f"label = <{simplify_label(label)}>"
        tag = tags.get(int(node_id))
        if tag is not None:
            color = SANITIZED_COLOR if str(tag).upper() == "TRUE" else UNSANITIZED_COLOR
            attributes += f', fillcolor="{color}", style=filled'
        new_graph.write(f'"{node_id}" [{attributes}]\n')
