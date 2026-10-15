import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[1] / "scripts/page_resources.py"
spec = importlib.util.spec_from_file_location("page_resources", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PageResourcesTests(unittest.TestCase):
    resources = {"web/app.js": "text/javascript", "web/app.css": "text/css", "web/icon.png": "image/png"}

    def test_registered_classic_script_and_stylesheet(self):
        module.validate_page_resources('<link rel="stylesheet" href="./app.css"><script defer src="./app.js"></script>', self.resources)

    def test_registered_image_icon(self):
        module.validate_page_resources('<link rel="icon" href="icon.png">', self.resources)

    def test_data_favicon_rejected_like_host(self):
        with self.assertRaises(ValueError):
            module.validate_page_resources('<link rel="icon" href="data:,">', self.resources)

    def test_non_package_or_missing_references(self):
        for reference in ["https://example.com/icon.png", "//example.com/icon.png", "/icon.png", "../icon.png", "missing.png", "app.css?cache=1"]:
            with self.subTest(reference=reference), self.assertRaises(ValueError):
                module.validate_page_resources(f'<link rel="icon" href="{reference}">', self.resources)

    def test_module_scripts_wrong_mime_and_base_rejected(self):
        for source in ['<script type="module" src="app.js"></script>', '<link rel="icon" href="app.css">', '<base href="https://example.com/">']:
            with self.subTest(source=source), self.assertRaises(ValueError):
                module.validate_page_resources(source, self.resources)


if __name__ == "__main__":
    unittest.main()
