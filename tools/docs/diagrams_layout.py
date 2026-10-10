#!/usr/bin/env python3
"""Optional authoring helper: propose reviewed layouts with local Graphviz.

Graphviz is not needed to export, check, stage, or release committed diagrams.
Its version is recorded with the proposal. Review the gallery before committing.
"""
import argparse
import json
import subprocess
from pathlib import Path

from diagrams import HOME, catalog, edge_caption, semantic_digest, wrapped


def reviewable_json(value, indent=0):
    """Keep each node/edge record on one line, with graph structure expanded."""
    def simple(item):
        return not isinstance(item, dict) and (not isinstance(item, list) or all(simple(child) for child in item))
    if isinstance(value, dict) and not all(simple(item) for item in value.values()):
        lines = [" " * (indent + 2) + json.dumps(key) + ": " + reviewable_json(item, indent + 2) for key, item in value.items()]
        return "{\n" + ",\n".join(lines) + "\n" + " " * indent + "}"
    if isinstance(value, list) and not simple(value):
        return "[\n" + ",\n".join(" " * (indent + 2) + reviewable_json(item, indent + 2) for item in value) + "\n" + " " * indent + "]"
    return json.dumps(value, ensure_ascii=False)


def propose(spec, panel, direction, include_isolated):
    nodes = {node['id']: node for node in spec['nodes']}
    edges = {edge['id']: edge for edge in spec['edges']}
    selected = {edges[e][key] for e in panel['edges'] for key in ('source', 'target')}
    connected = {edge[key] for edge in edges.values() for key in ('source', 'target')}
    if include_isolated:
        selected |= {node['id'] for node in nodes.values() if node['id'] not in connected and not node['container'] and not node['parent']}
    lines = ['digraph G {', f'graph [rankdir={direction}, nodesep=0.4, ranksep=0.7, margin=0, pad=0, splines=spline];', 'node [shape=box, fixedsize=true, fontname="Helvetica", fontsize=16];', 'edge [fontname="Helvetica", fontsize=14, arrowsize=0.7];']
    for name in sorted(selected):
        node = nodes[name]
        height = max(82, len(wrapped(node['label'], 22)) * 25 + 34)
        width = 254
        if node['shape'] == 'rhombus':
            width, height = 350, max(140, height)
        if node['shape'] == 'start':
            width = height = 20
        shape = 'diamond' if node['shape'] == 'rhombus' else 'cylinder' if node['shape'] == 'cylinder' else 'box'
        lines.append(f'{json.dumps(name)} [shape={shape}, label="", width={width / 72}, height={height / 72}];')
    for edge_id in panel['edges']:
        edge = edges[edge_id]
        label = ', label=' + json.dumps(edge_caption(edge, list(edges).index(edge_id) + 1)) if edge['label'] else ''
        direction_attr = ', dir=both' if edge['bidirectional'] else ', dir=none' if edge['undirected'] else ''
        lines.append(f'{json.dumps(edge["source"])} -> {json.dumps(edge["target"])} [id="{edge_id}"{label}{direction_attr}];')
    lines.append('}')
    data = json.loads(subprocess.check_output(['dot', '-Tjson'], input='\n'.join(lines), text=True))
    _, _, w, h = map(float, data['bb'].split(','))
    result = {'width': w + 16, 'height': h + 16, 'nodes': {}, 'edges': {}}
    for obj in data['objects']:
        x, y = map(float, obj['pos'].split(','))
        nw, nh = float(obj['width']) * 72, float(obj['height']) * 72
        result['nodes'][obj['name']] = dict(x=round(x - nw / 2 + 8, 2), y=round(h - y - nh / 2 + 8, 2), w=round(nw, 2), h=round(nh, 2))
    for edge in data.get('edges', []):
        points = next(draw['points'] for draw in edge['_draw_'] if draw['op'] == 'b')
        label = list(map(float, edge['lp'].split(','))) if 'lp' in edge else [0, h]
        result['edges'][edge['id']] = {'points': [[round(x + 8, 2), round(h - y + 8, 2)] for x, y in points], 'label': [round(label[0] + 8, 2), round(h - label[1] + 8, 2)]}
    degrees = {node: sum(edges[e]['target'] == node for e in panel['edges']) for node in selected}
    result['focus'] = max(sorted(degrees), key=degrees.get)
    return result


def layout(spec):
    panels = []
    for index, panel in enumerate(spec['panels']):
        candidates = [propose(spec, panel, direction, index == 0) for direction in ('TB', 'LR')]
        candidates.sort(key=lambda c: (c['width'] > 1000, max(c['width'] / 880, 1) * c['height']))
        panels.append(candidates[0])
    return {'semanticDigest': semantic_digest(spec), 'authoringTool': subprocess.check_output(['dot', '-V'], stderr=subprocess.STDOUT, text=True).strip(), 'panels': panels}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ids', nargs='+', help='Catalog ids, or all')
    args = parser.parse_args()
    known = {entry['id']: entry['spec'] for entry in catalog()}
    names = list(known) if args.ids == ['all'] else args.ids
    for name in names:
        spec = known[name]
        if spec['kind'] == 'sequence' or name == 'readme-2':
            continue
        result = layout(spec)
        (HOME / 'layouts' / f'{name}.json').write_text(reviewable_json(result) + '\n')
        print(name, [(round(p['width']), round(p['height'])) for p in result['panels']])


if __name__ == '__main__':
    main()
