"""Validate HTML references against the RS isolated-page package boundary."""
from html.parser import HTMLParser
from pathlib import PurePosixPath
from urllib.parse import urlsplit


def validate_page_resources(source, resources, entry="web/index.html"):
    class PageParser(HTMLParser):
        def handle_starttag(self, tag, attrs):
            fields = dict(attrs)
            if tag == "base":
                raise ValueError("Page base URLs are not allowed")
            if tag not in {"link", "script"}:
                return
            reference = fields.get("href" if tag == "link" else "src")
            if reference is None:
                return
            url = urlsplit(reference)
            if url.scheme or url.netloc or url.query or url.fragment or not url.path or url.path.startswith("/"):
                raise ValueError("Page resource must be a relative package reference")
            parts = PurePosixPath(url.path).parts
            if ".." in parts:
                raise ValueError("Page resource escapes the entry directory")
            path = str(PurePosixPath(entry).parent.joinpath(*parts))
            mime = resources.get(path)
            if mime is None:
                raise ValueError("Page references an undeclared resource")
            if tag == "script":
                if fields.get("type") == "module" or mime not in {"text/javascript", "application/javascript"}:
                    raise ValueError("Page scripts must be packaged classic JavaScript")
            else:
                rel = set(fields.get("rel", "").split())
                if not rel or not rel <= {"stylesheet", "icon"}:
                    raise ValueError("Unsupported page link type")
                if "stylesheet" in rel and mime != "text/css":
                    raise ValueError("Stylesheet resource must be CSS")
                if "icon" in rel and not mime.startswith("image/"):
                    raise ValueError("Icon resource must be an image")

    parser = PageParser(convert_charrefs=True)
    parser.feed(source)
    parser.close()
