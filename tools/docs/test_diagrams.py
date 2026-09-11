#!/usr/bin/env python3
"""Regression tests for diagram fidelity and the publication boundary."""
import copy
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import diagrams as d


class DiagramTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entries = d.catalog()
        cls.specs = {entry['id']: entry['spec'] for entry in cls.entries}

    def test_catalog_covers_migrated_public_diagrams(self):
        self.assertGreaterEqual(len(self.entries), 30)
        self.assertEqual(4 * len(self.entries), len([p for p in d.outputs(self.entries) if p.suffix == '.svg']))

    def test_palette_matches_the_public_site(self):
        import re
        css = (d.ROOT / 'docs/site/assets/stylesheets/extra.css').read_text()
        selectors = {'light': r':root\s*\{([^}]+)', 'dark': r'\[data-md-color-scheme="slate"\]\s*\{([^}]+)'}
        for theme, pattern in selectors.items():
            block = re.search(pattern, css)[1]
            for role, value in d.THEMES[theme].items():
                if role == 'paper':
                    self.assertIn(value, block)
                else:
                    name = 'accent-soft' if role == 'soft' else role
                    self.assertRegex(block, '--webauthn-' + name + r':\s*' + value)

    def test_long_symbols_break_at_identifier_boundaries(self):
        self.assertEqual(['PublicKeyCredential', 'RequestOptions'], d.wrapped('PublicKeyCredentialRequestOptions', 24))
        self.assertEqual(['PasskeyClient.', 'getAssertion'], d.wrapped('PasskeyClient.getAssertion', 24))

    def test_unknown_endpoint_is_rejected(self):
        spec = copy.deepcopy(self.specs['readme-1'])
        spec['edges'][0]['target'] = 'missing'
        with self.assertRaisesRegex(ValueError, 'Dangling'):
            d.validate(spec)

    def test_split_view_cannot_drop_or_duplicate_edges(self):
        for mutation in ('drop', 'duplicate'):
            spec = copy.deepcopy(self.specs['docs-architecture-3'])
            if mutation == 'drop':
                spec['panels'][0]['edges'].pop()
            else:
                spec['panels'][0]['edges'].append(spec['panels'][0]['edges'][0])
            with self.assertRaisesRegex(ValueError, 'exactly once'):
                d.validate(spec)

    def test_sequence_cannot_reorder_ceremony_messages(self):
        spec = copy.deepcopy(self.specs['readme-1'])
        spec['phases'][0]['edges'].reverse()
        with self.assertRaisesRegex(ValueError, 'message order'):
            d.validate(spec)

    def test_missing_group_is_rejected(self):
        spec = copy.deepcopy(self.specs['public-architecture-1'])
        spec['nodes'][1]['parent'] = 'unknown'
        with self.assertRaisesRegex(ValueError, 'membership'):
            d.validate(spec)

    def test_layout_cannot_hide_isolated_runtime(self):
        spec = self.specs['docs-architecture-2']
        layout = json.loads((d.HOME / 'layouts/docs-architecture-2.json').read_text())
        del layout['panels'][0]['nodes']['RUNTIME']
        with self.assertRaisesRegex(ValueError, 'isolated'):
            d.validate_layout(spec, layout)

    def test_layout_cannot_hide_relationship(self):
        spec = self.specs['docs-architecture-2']
        layout = json.loads((d.HOME / 'layouts/docs-architecture-2.json').read_text())
        layout['panels'][0]['edges'].pop('e1')
        with self.assertRaisesRegex(ValueError, 'relationship'):
            d.validate_layout(spec, layout)

    def test_svg_rejects_script_external_references_and_events(self):
        for payload in ('<script/>', '<image href="https://example.com/a.svg"/>', '<g onclick="alert(1)"/>', '<rect fill="url(https://example.com/paint.svg)"/>', '<style>@import "https://example.com/font";</style>'):
            with self.assertRaises(ValueError):
                d.safe_svg(f'<svg xmlns="http://www.w3.org/2000/svg"><title>t</title><desc>d</desc>{payload}</svg>')

    def test_stale_layout_is_rejected_after_semantic_change(self):
        spec = copy.deepcopy(self.specs['docs-architecture-2'])
        spec['edges'][0]['target'] = 'RUNTIME'
        with self.assertRaisesRegex(ValueError, 'Stale layout'):
            d.graph_svg(spec, 'light')

    def test_mobile_preserves_direction_optional_edges_and_groups(self):
        svg = d.mobile_svg(self.specs['docs-architecture-1'], 'light')
        self.assertIn('stroke-dasharray="6 5"', svg)
        self.assertIn('data-from="BACKEND" data-to="CLIENT"', svg)
        self.assertIn('Reference passkey application', svg)
        svg = d.mobile_svg(self.specs['public-architecture-1'], 'dark')
        self.assertIn('marker-start=', svg)
        for label in ('Models', 'Binary protocol', 'Extension hooks'):
            self.assertIn(label, svg)

    def test_github_and_relocated_site_paths(self):
        spec = self.specs['core-webauthn-core-readme-1']
        github = d.embed(spec, 'core/webauthn-core/README.md')
        site = d.embed(spec, 'reference/modules/webauthn-core.md', site=True)
        self.assertIn('../../docs/diagrams/assets/', github)
        # GitHub rewrites theme media queries; no phone source may be selected
        # by that rewrite on desktop. Phone views remain explicit links.
        picture = github.split('<picture>')[1].split('</picture>')[0]
        self.assertNotIn('-mobile-', picture)
        self.assertNotIn('max-width:', picture)
        self.assertIn('width="640"', picture)
        self.assertIn('-mobile-dark.svg">dark</a>', github)
        self.assertIn('../../../assets/diagrams/', site)
        self.assertIn('(max-width: 720px)', site)
        self.assertIn('class="diagram-dark"', site)
        self.assertNotIn('prefers-color-scheme', site)
        home = d.embed(spec, 'index.md', site=True)
        self.assertIn('src="assets/diagrams/', home)

    def test_update_detects_stale_export_without_rewriting(self):
        target = d.HOME / 'assets/readme-1-desktop-light.svg'
        original = Path.read_text
        def stale(path, *args, **kwargs):
            return 'stale' if path == target else original(path, *args, **kwargs)
        with mock.patch.object(Path, 'read_text', stale), self.assertRaisesRegex(ValueError, 'Stale diagram outputs'):
            d.sync(check=True)

    def test_package_is_deterministic_and_commit_pinned(self):
        with tempfile.TemporaryDirectory(dir=d.ROOT / 'build') as temporary:
            first, second = Path(temporary) / 'first.zip', Path(temporary) / 'second.zip'
            with mock.patch.object(d, 'sync'):
                d.package(first, 'a' * 40)
                d.package(second, 'a' * 40)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as archive:
                provenance = json.loads(archive.read('provenance.json'))
                self.assertEqual('a' * 40, provenance['sourceRef'])
                self.assertIn('gallery.html', provenance['files'])
                self.assertIn('THIRD_PARTY_NOTICES.md', archive.namelist())
                self.assertTrue(all(not name.startswith('/') and '..' not in Path(name).parts for name in archive.namelist()))

    def test_output_path_cannot_escape_build(self):
        with mock.patch.object(d, 'sync'), self.assertRaises(ValueError):
            d.package(d.ROOT / 'outside.zip', 'a' * 40)


if __name__ == '__main__':
    (d.ROOT / 'build').mkdir(exist_ok=True)
    unittest.main(verbosity=2)
