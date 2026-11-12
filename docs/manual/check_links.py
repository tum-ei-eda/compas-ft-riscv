#!/usr/bin/env python3
"""Check generated Pages links, assets and HTML fragments without network access."""

import argparse
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit


class Document(HTMLParser):
    def __init__(self, path):
        super().__init__(convert_charrefs=True)
        self.anchors = set()
        self.links = []
        self.feed(path.read_text(encoding="utf-8"))

    def handle_starttag(self, tag, attributes):
        attributes = dict(attributes)
        if attributes.get("id"):
            self.anchors.add(attributes["id"])
        if tag == "a" and attributes.get("name"):
            self.anchors.add(attributes["name"])
        for name in ("href", "src"):
            if attributes.get(name):
                self.links.append(attributes[name])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("site", type=Path, help="generated Pages directory")
    root = parser.parse_args().site.resolve()
    documents = {path: Document(path) for path in root.rglob("*.html")}
    if not documents:
        parser.error(f"no HTML pages found in {root}")

    errors = []
    checked = 0
    for source, document in list(documents.items()):
        for link in document.links:
            url = urlsplit(link)
            if url.scheme or url.netloc:
                continue
            checked += 1
            label = f"{source.relative_to(root)}: {link}"
            if url.path.startswith("/"):
                errors.append(f"{label}: use a relative link for project Pages")
                continue
            target = (source.parent / unquote(url.path)).resolve() if url.path else source
            if not target.is_relative_to(root):
                errors.append(f"{label}: link leaves the generated site")
                continue
            if target.is_dir():
                target /= "index.html"
            if not target.is_file():
                errors.append(f"{label}: missing file")
            elif url.fragment and target.suffix == ".html":
                if target not in documents:
                    documents[target] = Document(target)
                if unquote(url.fragment) not in documents[target].anchors:
                    errors.append(f"{label}: missing HTML anchor")

    for error in errors:
        print(error)
    print(f"Checked {checked} local links in {len(documents)} pages; {len(errors)} errors.")
    return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())
