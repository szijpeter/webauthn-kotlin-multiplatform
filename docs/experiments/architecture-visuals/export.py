#!/usr/bin/env python3
"""Export this one experiment and check its relationship/label fidelity.

Only Python's standard library is required. Mermaid PNGs are rendered separately
with the repository's existing mmdc tooling; this does not install dependencies.
"""

import argparse
import re
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
SVG_NS = {"svg": "http://www.w3.org/2000/svg"}


def normalize(label):
    return " ".join(re.sub(r"<br\s*/?>", " ", label).split())


def mermaid_model(source):
    nodes = {
        name: normalize(label)
        for name, label in re.findall(r'(\w+)\["([^"]+)"\]', source)
    }
    edges = re.findall(r"(\w+) -{2,}> (\w+)", source)
    return nodes, sorted(edges)


def exports():
    source = (HERE / "editorial.html").read_text()
    css = re.search(r'<style id="diagram-style">(.*?)</style>', source, re.S)[1].strip()
    # Standalone variants must stay visible regardless of the viewing window.
    css += "\nsvg.desktop, svg.mobile { display: block !important; }\n"
    before = mermaid_model((HERE / "before.mmd").read_text())
    refined = mermaid_model((HERE / "refined.mmd").read_text())
    if before != refined:
        raise ValueError("Refined Mermaid changed a node label or relationship")
    diagrams = re.findall(r'<svg class="(desktop|mobile)".*?</svg>', source, re.S)
    if diagrams != ["desktop", "mobile"]:
        raise ValueError("Expected exactly the desktop and mobile diagrams")
    outputs = {}
    for variant in diagrams:
        svg = re.search(rf'<svg class="{variant}".*?</svg>', source, re.S)[0]
        tree = ET.fromstring(svg)
        nodes = {
            node.attrib["data-node"]: normalize(" ".join(
                "".join(text.itertext()) for text in node.findall("svg:text", SVG_NS)
            ))
            for node in tree.findall(".//svg:g[@data-node]", SVG_NS)
        }
        edges = sorted(
            (edge.attrib["data-from"], edge.attrib["data-to"])
            for edge in tree.findall(".//svg:path[@data-from]", SVG_NS)
        )
        if (nodes, edges) != before:
            raise ValueError(f"{variant}: node labels or relationships changed")
        for theme in ("light", "dark"):
            _, _, width, height = tree.attrib["viewBox"].split()
            output = svg.replace(
                '<svg ', f'<svg width="{width}" height="{height}" data-theme="{theme}" ', 1
            )
            output = output.replace("<defs>", f"<defs><style>{css}</style>", 1)
            # Each export also has unique IDs when inlined alongside other themes.
            output = output.replace(f"overview-{variant}-", f"overview-{variant}-{theme}-")
            output = output.replace(f'{variant}-arrow', f'{variant}-{theme}-arrow')
            output = '<?xml version="1.0" encoding="UTF-8"?>\n' + output + "\n"
            ET.fromstring(output)
            outputs[HERE / "assets" / f"editorial-{variant}-{theme}.svg"] = output
    return outputs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="check without writing")
    args = parser.parse_args()
    outputs = exports()
    for path, content in outputs.items():
        if args.check:
            if not path.is_file() or path.read_text() != content:
                raise SystemExit(f"Stale export: {path.name}; run export.py")
        else:
            path.parent.mkdir(exist_ok=True)
            path.write_text(content)
    print("PASS: all three approaches preserve 5 labels and 6 directed relationships")
    print(f"PASS: {len(outputs)} SVG exports {'current' if args.check else 'written'}")


if __name__ == "__main__":
    main()
