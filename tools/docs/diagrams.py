#!/usr/bin/env python3
"""Deterministic, offline diagram export, embedding, validation and release packaging."""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import posixpath
import re
import sys
import textwrap
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HOME = ROOT / 'docs/diagrams'
ID = re.compile(r'[a-z0-9][a-z0-9-]*\Z')
BLOCK = re.compile(r'<!-- diagram: ([a-z0-9-]+) -->\n.*?<!-- /diagram -->', re.S)
THEMES = {
    'light': dict(paper='#ffffff', ink='#293545', muted='#667386', line='#d8dee7', panel='#f3f5f7', accent='#316da8', soft='#e8f0f8'),
    'dark': dict(paper='#1d242d', ink='#edf1f5', muted='#b4bfcc', line='#3c4755', panel='#28313d', accent='#82b5e8', soft='#263f58'),
}
NS = {'s': 'http://www.w3.org/2000/svg'}


def escape(value):
    return html.escape(str(value), quote=True)


def inside(path, root=ROOT):
    path = path.resolve()
    path.relative_to(root.resolve())
    return path


def wrapped(label, width=30):
    lines = []
    for part in label.splitlines():
        for line in textwrap.wrap(part, width, break_long_words=False, break_on_hyphens=True) or ['']:
            while len(line) > width:
                natural = [match.end() for match in re.finditer(r'[. /_-]', line[:width])]
                camel = [match.start() for match in re.finditer(r'(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])', line[:width + 1])]
                choices = [position for position in natural if position >= width / 3] or camel
                cut = max(choices) if choices else width
                lines.append(line[:cut].rstrip())
                line = line[cut:].lstrip()
            lines.append(line)
    return lines


def edge_caption(edge, index):
    return edge['label'] if len(edge['label']) <= 18 else str(index)


def semantic_digest(spec):
    fields = {key: spec[key] for key in ('nodes', 'edges', 'panels')}
    return hashlib.sha256(json.dumps(fields, sort_keys=True).encode()).hexdigest()


def validate(spec):
    if not ID.fullmatch(spec['id']):
        raise ValueError('Invalid diagram id')
    if spec['kind'] not in ('graph', 'sequence', 'state'):
        raise ValueError('Unknown diagram kind')
    nodes = {node['id']: node for node in spec['nodes']}
    edges = {edge['id']: edge for edge in spec['edges']}
    if len(nodes) != len(spec['nodes']) or len(edges) != len(spec['edges']):
        raise ValueError('Duplicate node or edge id')
    for node in nodes.values():
        if node['shape'] not in ('actor', 'container', 'cylinder', 'lifeline', 'rect', 'rhombus', 'stadium', 'start', 'state'):
            raise ValueError('Unsupported node shape')
        parent = node['parent']
        if parent and (parent not in nodes or not nodes[parent]['container']):
            raise ValueError('Unknown group membership')
        if parent == node['id']:
            raise ValueError('Self-containing group')
    for edge in edges.values():
        if edge['source'] not in nodes or edge['target'] not in nodes:
            raise ValueError('Dangling relationship')
        if edge['style'] not in ('solid', 'dashed', 'thick', 'dotted'):
            raise ValueError('Unknown relationship style')
    assigned = [edge for panel in spec['panels'] for edge in panel['edges']]
    if sorted(assigned) != sorted(edges):
        raise ValueError('Panels must cover every relationship exactly once')
    if spec['kind'] == 'sequence':
        ordered = [edge for phase in spec['phases'] for edge in phase['edges']]
        if ordered != list(edges):
            raise ValueError('Sequence phases changed message order')


def catalog():
    entries = json.loads((HOME / 'catalog.json').read_text())
    ids = [entry['id'] for entry in entries]
    if len(ids) != len(set(ids)) or any(not ID.fullmatch(name) for name in ids):
        raise ValueError('Invalid or duplicate catalog id')
    sources = {path.stem for path in (HOME / 'sources').glob('*.json')}
    if sources != set(ids):
        raise ValueError('Catalog and source files differ')
    for entry in entries:
        inside(ROOT / entry['page'])
        entry['spec'] = json.loads((HOME / 'sources' / (entry['id'] + '.json')).read_text())
        validate(entry['spec'])
        if entry['id'] != entry['spec']['id']:
            raise ValueError('Source id differs from filename')
    return entries


class Canvas:
    def __init__(self, spec, theme, variant, width):
        self.spec, self.width = spec, width
        self.theme, self.variant = theme, variant
        self.prefix = f"{spec['id']}-{variant}-{theme}"
        self.parts = []

    def add(self, value):
        self.parts.append(value)

    def text(self, x, y, value, size=16, color='ink', weight=400, anchor='start', attrs=''):
        self.add(f'<text x="{x:.2f}" y="{y:.2f}" font-size="{size}" fill="var(--{color})" font-weight="{weight}" text-anchor="{anchor}" {attrs}>{escape(value)}</text>')

    def lines(self, x, y, value, width, size=16, color='ink', weight=400, anchor='start'):
        lines = wrapped(value, width)
        for i, line in enumerate(lines):
            self.text(x, y + i * (size + 6), line, size, color, weight, anchor)
        return len(lines) * (size + 6)

    def box(self, x, y, w, h, fill='paper', stroke='line', radius=10, attrs=''):
        self.add(f'<rect x="{x:.2f}" y="{y:.2f}" width="{w:.2f}" height="{h:.2f}" rx="{radius}" fill="var(--{fill})" stroke="var(--{stroke})" {attrs}/>')

    def edge(self, d, edge, label=None):
        dashed = ' stroke-dasharray="6 5"' if edge['style'] in ('dashed', 'dotted') else ''
        end = '' if edge['undirected'] else f' marker-end="url(#{self.prefix}-arrow)"'
        start = f' marker-start="url(#{self.prefix}-arrow)"' if edge['bidirectional'] else ''
        self.add(f'<path d="{d}" fill="none" stroke="var(--muted)" stroke-width="1.7" stroke-linejoin="round" stroke-linecap="round"{dashed}{start}{end} data-edge="{escape(edge["id"])}" data-from="{escape(edge["source"])}" data-to="{escape(edge["target"])}"/>')
        if label:
            x, y, text = label
            width = max(26, len(text) * 7.5 + 16)
            self.box(x - width / 2, y - 13, width, 26, 'paper', 'line', 7)
            self.text(x, y + 5, text, 14, 'accent', 650, 'middle')

    def finish(self, height):
        colors = ';'.join(f'--{key}:{value}' for key, value in THEMES[self.theme].items())
        description = transcript(self.spec, plain=True)
        start = f'''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="{self.width}" height="{height:.0f}" viewBox="0 0 {self.width} {height:.0f}" role="img" aria-labelledby="{self.prefix}-title {self.prefix}-desc" data-diagram="{self.spec['id']}">
<title id="{self.prefix}-title">{escape(self.spec['title'])}</title>
<desc id="{self.prefix}-desc">{escape(description)}</desc>
<defs><style>svg{{{colors};font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif}}text{{font-kerning:normal}}</style>
<marker id="{self.prefix}-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto-start-reverse" markerUnits="userSpaceOnUse"><path d="M 0 1 L 7 4 L 0 7 Z" fill="{THEMES[self.theme]['muted']}"/></marker></defs>
<rect width="100%" height="100%" rx="16" fill="var(--paper)"/>
'''
        return start + '\n'.join(self.parts) + '\n</svg>\n'


def heading(canvas, mobile=False):
    width = 32 if mobile else 88
    canvas.text(24 if mobile else 32, 34, 'WEBAUTHN · ' + ('CEREMONY' if canvas.spec['kind'] == 'sequence' else 'ARCHITECTURE'), 11, 'accent', 650)
    y = 65 + canvas.lines(24 if mobile else 32, 65, canvas.spec['title'], width, 23 if mobile else 28, weight=700)
    y += canvas.lines(24 if mobile else 32, y + 2, canvas.spec['summary'], 37 if mobile else 96, 14, 'muted')
    return y + 25


def transcript(spec, plain=False):
    nodes = {node['id']: node for node in spec['nodes']}
    lines = [spec['summary'], 'Nodes: ' + '; '.join(node['label'].replace('\n', ' — ') for node in nodes.values()) + '.']
    for node in nodes.values():
        if node['parent']:
            lines.append(f"{node['label']} belongs to {nodes[node['parent']]['label']}.")
    if spec['notes']:
        lines.append('Notes: ' + '; '.join(spec['notes']) + '.')
    for i, edge in enumerate(spec['edges'], 1):
        symbol = '↔' if edge['bidirectional'] else '—' if edge['undirected'] else '→'
        suffix = f": {edge['label']}" if edge['label'] else ''
        style = ' (dashed)' if edge['style'] in ('dashed', 'dotted') else ''
        lines.append(f"{i}. {nodes[edge['source']]['label']} {symbol} {nodes[edge['target']]['label']}{suffix}{style}.")
    return '\n'.join(line.replace('\n', ' ') for line in lines if line)


def mobile_svg(spec, theme):
    canvas = Canvas(spec, theme, 'mobile', 400)
    y = heading(canvas, True)
    nodes = {node['id']: node for node in spec['nodes']}
    edges = {edge['id']: edge for edge in spec['edges']}
    sections = spec['phases'] if spec['kind'] == 'sequence' else spec['panels']
    for panel in sections:
        if len(sections) > 1:
            y += canvas.lines(24, y + 10, panel['title'], 33, 18, weight=650) + 23
        for edge_id in panel['edges']:
            edge = edges[edge_id]
            source, target = nodes[edge['source']], nodes[edge['target']]
            source_lines, target_lines = wrapped(source['label'], 28), wrapped(target['label'], 28)
            relation = edge['label']
            rel_lines = wrapped(relation, 30) or ['']
            h = 78 + 24 * (len(source_lines) + len(target_lines)) + 22 * len(rel_lines)
            canvas.box(24, y, 352, h, 'panel', 'line')
            canvas.text(40, y + 26, f"{list(edges).index(edge_id) + 1:02d}", 12, 'accent', 700)
            canvas.add(f'<g data-node="{escape(source["id"])}">')
            canvas.lines(40, y + 52, source['label'], 28, 18, weight=650)
            canvas.add('</g>')
            ey = y + 60 + 24 * len(source_lines)
            canvas.edge(f'M 49 {ey} L 49 {ey + 22 * len(rel_lines)}', edge)
            canvas.lines(68, ey + 12, relation, 30, 16, 'muted')
            ty = ey + 22 * len(rel_lines) + 26
            canvas.add(f'<g data-node="{escape(target["id"])}">')
            canvas.lines(40, ty, target['label'], 28, 18, weight=650)
            canvas.add('</g>')
            y += h + 16
    connected = {edge[key] for edge in spec['edges'] for key in ('source', 'target')}
    extras = [node for node in spec['nodes'] if node['id'] not in connected or node['parent']]
    if extras:
        y += canvas.lines(24, y + 16, 'Additional context', 32, 18, weight=650) + 20
        for node in extras:
            label = node['label']
            if node['parent']:
                label += ' · in ' + nodes[node['parent']]['label']
            elif node['id'] not in connected and not node['container']:
                label += ' · no drawn relationships'
            canvas.add(f'<g data-node="{escape(node["id"])}">')
            y += canvas.lines(24, y + 8, label, 34, 16, 'muted') + 15
            canvas.add('</g>')
    return canvas.finish(y + 16)


def validate_layout(spec, layout):
    import math
    edges = {edge['id']: edge for edge in spec['edges']}
    nodes = {node['id']: node for node in spec['nodes']}
    if len(layout['panels']) != len(spec['panels']):
        raise ValueError('Layout panel count differs')
    visible = set()
    for panel, geometry in zip(spec['panels'], layout['panels'], strict=True):
        if set(geometry['edges']) != set(panel['edges']):
            raise ValueError('Layout dropped or added a relationship')
        if not set(geometry['nodes']) <= set(nodes):
            raise ValueError('Layout contains an unknown node')
        required = {edges[e][key] for e in panel['edges'] for key in ('source', 'target')}
        if not required <= set(geometry['nodes']):
            raise ValueError('Layout dropped a relationship endpoint')
        visible.update(geometry['nodes'])
        boxes = list(geometry['nodes'].values())
        for box in boxes:
            if any(not math.isfinite(box[key]) for key in ('x', 'y', 'w', 'h')):
                raise ValueError('Non-finite layout coordinate')
            if box['w'] <= 0 or box['h'] <= 0 or box['x'] < -1 or box['y'] < -1 or box['x'] + box['w'] > geometry['width'] + 1 or box['y'] + box['h'] > geometry['height'] + 1:
                raise ValueError('Node outside canvas')
        for i, a in enumerate(boxes):
            for b in boxes[i + 1:]:
                if a['x'] < b['x'] + b['w'] and b['x'] < a['x'] + a['w'] and a['y'] < b['y'] + b['h'] and b['y'] < a['y'] + a['h']:
                    raise ValueError('Overlapping diagram nodes')
        for edge_id, edge in geometry['edges'].items():
            endpoints = {edges[edge_id]['source'], edges[edge_id]['target']}
            if len(edge['points']) < 4 or (len(edge['points']) - 1) % 3:
                raise ValueError('Malformed cubic connector')
            if any(not math.isfinite(v) for point in edge['points'] for v in point):
                raise ValueError('Non-finite connector')
            for offset in range(0, len(edge['points']) - 1, 3):
                control = edge['points'][offset:offset + 4]
                for step in range(21):
                    t = step / 20
                    weights = ((1-t)**3, 3*(1-t)**2*t, 3*(1-t)*t*t, t**3)
                    x, y = [sum(weights[i] * control[i][axis] for i in range(4)) for axis in (0, 1)]
                    if not -1 <= x <= geometry['width'] + 1 or not -1 <= y <= geometry['height'] + 1:
                        raise ValueError('Connector outside canvas')
                    for name, box in geometry['nodes'].items():
                        if name not in endpoints and box['x'] + 1 < x < box['x'] + box['w'] - 1 and box['y'] + 1 < y < box['y'] + box['h'] - 1:
                            raise ValueError('Connector crosses a non-endpoint node')
    # Group members also appear explicitly in the membership legend.
    missing = {name for name, node in nodes.items() if not node['container'] and not node['parent']} - visible
    if missing:
        raise ValueError(f'Layout dropped isolated nodes: {sorted(missing)}')


def graph_svg(spec, theme):
    layout = json.loads((HOME / 'layouts' / (spec['id'] + '.json')).read_text())
    if layout['semanticDigest'] != semantic_digest(spec):
        raise ValueError(f"Stale layout: {spec['id']}; run diagrams_layout.py {spec['id']}")
    validate_layout(spec, layout)
    canvas = Canvas(spec, theme, 'desktop', 960)
    y = heading(canvas)
    nodes = {node['id']: node for node in spec['nodes']}
    edges = {edge['id']: edge for edge in spec['edges']}
    for panel, geometry in zip(spec['panels'], layout['panels'], strict=True):
        if len(spec['panels']) > 1:
            canvas.text(32, y + 20, panel['title'], 20, weight=650)
            y += 42
        scale = min(1.0, 880 / geometry['width'])
        if scale < 0.72:
            raise ValueError(f"Split wide panel: {spec['id']} / {panel['title']}")
        ox = (960 - geometry['width'] * scale) / 2
        def point(p):
            return (ox + p[0] * scale, y + p[1] * scale)
        for edge_id, geo in geometry['edges'].items():
            pts = [point(p) for p in geo['points']]
            d = f'M {pts[0][0]:.2f} {pts[0][1]:.2f} C ' + ' '.join(f'{x:.2f} {yy:.2f}' for x, yy in pts[1:])
            label = None
            if edges[edge_id]['label']:
                lx, ly = point(geo['label'])
                label = lx, ly, edge_caption(edges[edge_id], list(edges).index(edge_id) + 1)
            canvas.edge(d, edges[edge_id], label)
        for node_id, geo in geometry['nodes'].items():
            node = nodes[node_id]
            x, yy = point([geo['x'], geo['y']])
            w, h = geo['w'] * scale, geo['h'] * scale
            canvas.add(f'<g data-node="{escape(node_id)}">')
            focal = node_id == geometry['focus']
            if node['shape'] == 'start':
                canvas.add(f'<circle cx="{x + w / 2}" cy="{yy + h / 2}" r="7" fill="var(--ink)"/>')
            else:
                fill, stroke = ('soft', 'accent') if focal else ('panel', 'line')
                if node['shape'] == 'rhombus':
                    canvas.add(f'<polygon points="{x+w/2},{yy} {x+w},{yy+h/2} {x+w/2},{yy+h} {x},{yy+h/2}" fill="var(--{fill})" stroke="var(--{stroke})"/>')
                elif node['shape'] == 'cylinder':
                    r = 12 * scale
                    canvas.add(f'<path d="M {x} {yy+r} C {x} {yy-r/3} {x+w} {yy-r/3} {x+w} {yy+r} V {yy+h-r} C {x+w} {yy+h+r/3} {x} {yy+h+r/3} {x} {yy+h-r} Z" fill="var(--{fill})" stroke="var(--{stroke})"/>')
                    canvas.add(f'<path d="M {x} {yy+r} C {x} {yy+r*2.3} {x+w} {yy+r*2.3} {x+w} {yy+r}" fill="none" stroke="var(--{stroke})"/>')
                else:
                    canvas.box(x, yy, w, h, fill, stroke, 20 if node['shape'] in ('state', 'stadium') else 9, 'stroke-dasharray="5 4"' if node['container'] else '')
                lines = wrapped(node['label'], 22)
                fs = 20 * scale
                ty = yy + (h - len(lines) * (fs + 5 * scale)) / 2 + fs
                for line in lines:
                    canvas.text(x + w / 2, ty, line, round(fs, 2), 'ink', 600, 'middle')
                    ty += fs + 5 * scale
            canvas.add('</g>')
        y += geometry['height'] * scale + 22
        for edge_id in panel['edges']:
            edge = edges[edge_id]
            if len(edge['label']) > 18:
                canvas.text(36, y + 18, f'{list(edges).index(edge_id) + 1:02d}', 14, 'accent', 700)
                y += canvas.lines(70, y + 18, edge['label'], 85, 17, 'muted') + 8
        y += 20
    groups = [node for node in spec['nodes'] if node['container']]
    if groups:
        canvas.text(32, y + 16, 'Group membership', 17, weight=650)
        y += 45
        for group in groups:
            members = [node['label'].replace('\n', ' — ') for node in spec['nodes'] if node['parent'] == group['id']]
            canvas.add(f'<g data-node="{escape(group["id"])}">')
            y += canvas.lines(32, y, group['label'] + ': ' + '; '.join(members), 90, 17, 'muted') + 14
            canvas.add('</g>')
    return canvas.finish(y + 16)


def sequence_svg(spec, theme):
    canvas = Canvas(spec, theme, 'desktop', 960)
    y = heading(canvas)
    actors = spec['nodes']
    xs = {node['id']: 120 + i * 240 for i, node in enumerate(actors)}
    edges = {edge['id']: edge for edge in spec['edges']}
    for phase in spec['phases']:
        canvas.text(32, y + 20, phase['title'], 20, weight=650)
        y += 45
        for node in actors:
            x = xs[node['id']]
            canvas.add(f'<g data-node="{escape(node["id"])}">')
            canvas.box(x - 96, y, 192, 76, 'panel')
            canvas.lines(x, y + 28, node['label'], 22, 15, weight=650, anchor='middle')
            canvas.add('</g>')
        y += 92
        bottom = y + len(phase['edges']) * 90
        for x in xs.values():
            canvas.add(f'<path d="M {x} {y - 16} V {bottom}" stroke="var(--line)" stroke-dasharray="4 5"/>')
        for edge_id in phase['edges']:
            edge = edges[edge_id]
            x1, x2 = xs[edge['source']], xs[edge['target']]
            mid = (x1 + x2) / 2
            if x1 == x2:
                mid = x1 + 170
                path = f'M {x1} {y + 50} H {x1 + 48} V {y + 70} H {x1}'
            else:
                path = f'M {x1} {y + 50} H {x2}'
            label = f"{list(edges).index(edge_id) + 1:02d}  {edge['label']}"
            lines = wrapped(label, 55)
            maxw = max(map(len, lines)) * 7.6 + 20
            canvas.box(mid - maxw / 2, y + 2, maxw, len(lines) * 20 + 6, 'paper', 'paper', 4)
            canvas.lines(mid, y + 18, label, 55, 14, 'muted', anchor='middle')
            canvas.edge(path, edge)
            y += 90
        y += 30
    return canvas.finish(y + 20)


def overview_svg(spec, theme, variant):
    source = (HOME / 'templates/overview.html').read_text()
    css = re.search(r'<style id="diagram-style">(.*?)</style>', source, re.S)[1].strip()
    css += '\nsvg.desktop, svg.mobile { display: block !important; }\n'
    svg = re.search(rf'<svg class="{variant}".*?</svg>', source, re.S)[0]
    tree = ET.fromstring(svg)
    actual_nodes = {node.attrib['data-node']: ' '.join(' '.join(text.itertext()).strip() for text in node.findall('s:text', NS)) for node in tree.findall('.//s:g[@data-node]', NS)}
    actual_nodes = {key: ' '.join(value.split()) for key, value in actual_nodes.items()}
    expected_nodes = {node['id']: ' '.join(node['label'].split()) for node in spec['nodes']}
    actual_edges = sorted((node.attrib['data-from'], node.attrib['data-to']) for node in tree.findall('.//s:path[@data-from]', NS))
    expected_edges = sorted((edge['source'], edge['target']) for edge in spec['edges'])
    if actual_nodes != expected_nodes or actual_edges != expected_edges:
        raise ValueError('Hand-authored overview changed labels or relationships; synchronize its source and template')
    _, _, width, height = tree.attrib['viewBox'].split()
    svg = svg.replace('<svg ', f'<svg width="{width}" height="{height}" data-theme="{theme}" ', 1)
    svg = svg.replace('<defs>', f'<defs><style>{css}</style>', 1)
    svg = svg.replace(f'overview-{variant}-', f'overview-{variant}-{theme}-').replace(f'{variant}-arrow', f'{variant}-{theme}-arrow')
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + svg + '\n'


def safe_svg(content):
    tree = ET.fromstring(content)
    allowed = {'svg', 'title', 'desc', 'defs', 'style', 'marker', 'path', 'rect', 'text', 'tspan', 'g', 'circle', 'line', 'polyline', 'polygon'}
    ids = set()
    for node in tree.iter():
        if node.tag.split('}')[-1] not in allowed:
            raise ValueError('Active or unsupported SVG element')
        for key, value in node.attrib.items():
            if any(not target.strip(" \"'").startswith('#') for target in re.findall(r'url\(([^)]+)\)', value, re.I)):
                raise ValueError('External SVG paint resource')
            if key.lower().startswith('on') or key.split('}')[-1] in ('href', 'src'):
                raise ValueError('External or active SVG attribute')
            if key == 'id':
                if value in ids:
                    raise ValueError('Duplicate SVG id')
                ids.add(value)
        if node.tag.endswith('style') and re.search(r'@import|https?:|url\(\s*["\x27]?(?!#)', node.text or '', re.I):
            raise ValueError('External CSS resource')
    if tree.find('s:title', NS) is None or tree.find('s:desc', NS) is None:
        raise ValueError('SVG lacks accessible title or description')
    return tree


def asset_name(name, variant, theme):
    return f'{name}-{variant}-{theme}.svg'


def picture(spec, prefix, theme=None, github=False):
    name = spec['id']
    attr = f' class="diagram-{theme}"' if theme else ''
    lines = [f'<picture{attr}>']
    variants = [('mobile', 'dark', '(max-width: 720px) and (prefers-color-scheme: dark)'), ('mobile', 'light', '(max-width: 720px)'), ('desktop', 'dark', '(prefers-color-scheme: dark)')]
    if theme:
        variants = [('mobile', theme, '(max-width: 720px)')]
    if github:
        # GitHub rewrites theme media queries, discarding combined width rules.
        # A mobile source here can therefore become a huge desktop image.
        variants = [('desktop', 'dark', '(prefers-color-scheme: dark)')]
    for variant, color, media in variants:
        lines.append(f'  <source media="{media}" srcset="{prefix}/{asset_name(name, variant, color)}">')
    width = 640 if github else 960
    lines.append(f'  <img alt="{escape(spec["title"] + ". " + spec["summary"])}" src="{prefix}/{asset_name(name, "desktop", theme or "light")}" width="{width}" loading="lazy">')
    lines.append('</picture>')
    return '\n'.join(lines)


def embed(spec, page, site=False):
    parent = Path(page).parent
    if site and Path(page).stem != 'index':
        parent = Path(page).with_suffix('')
    prefix = posixpath.relpath('assets/diagrams' if site else 'docs/diagrams/assets', str(parent))
    images = picture(spec, prefix, github=True) if not site else '<div class="diagram-figure">\n' + picture(spec, prefix, 'light') + '\n' + picture(spec, prefix, 'dark') + '\n</div>'
    paragraphs = ''.join('<p>' + escape(line) + '</p>\n' for line in transcript(spec).splitlines())
    if not site:
        images = f'<a href="{prefix}/{asset_name(spec["id"], "desktop", "light")}">\n{images}\n</a>'
        phone_links = ' · '.join(f'<a href="{prefix}/{asset_name(spec["id"], "mobile", color)}">{color}</a>' for color in THEMES)
        paragraphs = f'<p>Phone view: {phone_links}.</p>\n' + paragraphs
    return f'<!-- diagram: {spec["id"]} -->\n{images}\n<details>\n<summary>Diagram text: {escape(spec["title"])}</summary>\n{paragraphs}</details>\n<!-- /diagram -->'


def site_embeds(text, page):
    specs = {entry['id']: entry['spec'] for entry in catalog()}
    return BLOCK.sub(lambda match: embed(specs[match[1]], page, site=True), text)


def outputs(entries):
    result = {}
    for entry in entries:
        spec = entry['spec']
        for variant in ('desktop', 'mobile'):
            for theme in THEMES:
                if spec['id'] == 'readme-2':
                    svg = overview_svg(spec, theme, variant)
                elif variant == 'mobile':
                    svg = mobile_svg(spec, theme)
                elif spec['kind'] == 'sequence':
                    svg = sequence_svg(spec, theme)
                else:
                    svg = graph_svg(spec, theme)
                notice = (HOME / 'THIRD_PARTY_NOTICES.md').read_text().split('MIT License', 1)[1].strip()
                svg = svg.replace('?>\n', '?>\n<!-- Diagram Design adaptation. MIT License\n' + notice + '\n-->\n', 1)
                safe_svg(svg)
                result[HOME / 'assets' / asset_name(spec['id'], variant, theme)] = svg
    rows = []
    for entry in entries:
        spec = entry['spec']
        rows.append(f'<section id="{spec["id"]}">{picture(spec, "assets")}<details><summary>Diagram text</summary><pre>{escape(transcript(spec))}</pre></details></section>')
    result[HOME / 'gallery.html'] = '<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>WebAuthn diagram gallery</title><style>body{margin:0;padding:24px;font:16px system-ui;background:#f3f5f7;color:#293545}main{max-width:960px;margin:auto}section{margin:24px 0 64px}img{display:block;width:100%;height:auto}pre{white-space:pre-wrap}a{color:#316da8}@media(prefers-color-scheme:dark){body{background:#141b23;color:#edf1f5}a{color:#82b5e8}}</style></head><body><main><h1>WebAuthn diagrams</h1><p>Generated from reviewed semantic sources and layouts. Resize for the mobile view; system theme selects light or dark.</p>' + ''.join(rows) + '</main></body></html>\n'
    manifest = {str(path.relative_to(HOME)): hashlib.sha256(value.encode()).hexdigest() for path, value in result.items()}
    result[HOME / 'manifest.json'] = json.dumps({'schema': 1, 'diagrams': len(entries), 'sha256': manifest}, indent=2, sort_keys=True) + '\n'
    return result


def sync(check=False):
    entries = catalog()
    expected = outputs(entries)
    asset_paths = {path for path in expected if path.suffix == '.svg'}
    extras = set((HOME / 'assets').glob('*')) - asset_paths
    if extras:
        raise ValueError(f'Unregistered assets: {sorted(extras)}')
    page_specs = {}
    for entry in entries:
        page_specs.setdefault(entry['page'], {})[entry['id']] = entry['spec']
    for page, specs in page_specs.items():
        path = inside(ROOT / page)
        text = path.read_text()
        actual = [match[1] for match in BLOCK.finditer(text)]
        if sorted(actual) != sorted(specs):
            raise ValueError(f'Missing, duplicate or unknown diagram embeds: {page}')
        expected[path] = BLOCK.sub(lambda match: embed(specs[match[1]], page), text)
    failures = []
    for path, content in expected.items():
        if check:
            if not path.is_file() or path.read_text() != content:
                failures.append(str(path.relative_to(ROOT)))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
    if failures:
        raise ValueError('Stale diagram outputs; run python3 tools/docs/diagrams.py update:\n' + '\n'.join(failures))
    # Public diagrams must use this checked pipeline, including newly introduced pages.
    paths = [ROOT / 'README.md', *[p for folder in ('docs', 'client', 'core', 'server', 'sample') for p in (ROOT / folder).rglob('*.md') if 'build' not in p.parts]]
    for path in paths:
        if 'experiments' in path.parts:
            continue
        text = path.read_text()
        if re.search(r'^```mermaid\s*$', text, re.M):
            raise ValueError(f'Unmigrated Mermaid block: {path.relative_to(ROOT)}')
        if BLOCK.search(text) and path.relative_to(ROOT).as_posix() not in page_specs:
            raise ValueError(f'Unregistered diagram page: {path.relative_to(ROOT)}')
    print(f'PASS: {len(entries)} diagrams, {len(asset_paths)} safe SVG exports, catalog, transcripts and embeds {"current" if check else "updated"}')


def package(destination, source_ref):
    sync(check=True)
    if not re.fullmatch(r'[0-9a-f]{40}', source_ref):
        raise ValueError('Release source ref must be a full commit SHA')
    destination = inside(destination, ROOT / 'build')
    destination.parent.mkdir(parents=True, exist_ok=True)
    entries = catalog()
    files = [HOME / name for name in ('README.md', 'THIRD_PARTY_NOTICES.md', 'catalog.json', 'gallery.html', 'manifest.json', 'templates/overview.html')]
    for entry in entries:
        name = entry['id']
        files.append(HOME / 'sources' / f'{name}.json')
        if entry['spec']['kind'] != 'sequence' and name != 'readme-2':
            files.append(HOME / 'layouts' / f'{name}.json')
        files.extend(HOME / 'assets' / asset_name(name, variant, theme) for variant in ('desktop', 'mobile') for theme in THEMES)
    files.sort()
    for path in files:
        inside(path, HOME)
    provenance = {'sourceRef': source_ref, 'files': {str(path.relative_to(HOME)): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}}
    with zipfile.ZipFile(destination, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            info = zipfile.ZipInfo(path.relative_to(HOME).as_posix(), date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())
        archive.writestr(zipfile.ZipInfo('provenance.json', date_time=(1980, 1, 1, 0, 0, 0)), json.dumps(provenance, indent=2, sort_keys=True) + '\n')
    print(f'Packaged diagrams: {destination}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('update', 'check', 'package'))
    parser.add_argument('--output', type=Path, default=ROOT / 'build/diagrams/webauthn-diagrams.zip')
    parser.add_argument('--source-ref')
    args = parser.parse_args()
    if args.command == 'package':
        package(args.output, args.source_ref or '')
    else:
        sync(check=args.command == 'check')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, FileNotFoundError) as error:
        sys.exit(str(error))
