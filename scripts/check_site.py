#!/usr/bin/env python3
"""Check a Hugo build against the pre-migration URLs and local resources."""

import argparse
import json
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit
import xml.etree.ElementTree as ET


SITE_URL = "https://dimitrifourny.github.io/"


class Page(HTMLParser):
    def __init__(self, source):
        super().__init__(convert_charrefs=True)
        self.ids = set()
        self.links = []
        self.canonicals = []
        self.feed(source)

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if "id" in attrs:
            self.ids.add(attrs["id"])
        if tag in ("a", "link") and attrs.get("href"):
            if tag == "link" and attrs.get("rel") == "canonical":
                self.canonicals.append(attrs["href"])
            else:
                self.links.append(attrs["href"])
        if tag in ("img", "script", "source") and attrs.get("src"):
            self.links.append(attrs["src"])


def check_site(destination):
    root = destination.resolve()
    errors = []
    pages = {path: Page(path.read_text()) for path in root.rglob("*.html")}
    baseline = json.loads(Path(__file__).with_name("legacy-posts.json").read_text())
    origin = urlsplit(SITE_URL).netloc

    def local_file(url):
        path = root / unquote(urlsplit(url).path).lstrip("/")
        return path / "index.html" if path.is_dir() else path

    for url, original in baseline.items():
        path = local_file(url)
        if path not in pages:
            errors.append(f"Historical article missing: {url}")
            continue
        missing = set(original["ids"]) - pages[path].ids
        if missing:
            errors.append(f"Historical anchors missing at {url}: {sorted(missing)}")
        for image in original["images"]:
            target = urlsplit(urljoin(SITE_URL + url.lstrip("/"), image))
            if target.netloc == origin and not local_file(target.geturl()).is_file():
                errors.append(f"Historical image missing at {url}: {image}")

    for path, page in pages.items():
        relative = path.relative_to(root).as_posix()
        route = "/" + relative
        if route.endswith("/index.html"):
            route = route[:-len("index.html")]
        expected = urljoin(SITE_URL, route)
        if page.canonicals != [expected]:
            errors.append(f"Incorrect canonical on {route}: {page.canonicals}")
        for link in page.links:
            target = urlsplit(urljoin(expected, link))
            if target.scheme not in ("http", "https") or target.netloc != origin:
                continue
            file = local_file(target.geturl())
            if not file.is_file():
                errors.append(f"Broken local link on {route}: {link}")
            elif target.fragment and file in pages and unquote(target.fragment) not in pages[file].ids:
                errors.append(f"Broken anchor on {route}: {link}")

    documents = {}
    for path in root.rglob("*.xml"):
        try:
            documents[path.relative_to(root).as_posix()] = ET.parse(path)
        except ET.ParseError as error:
            errors.append(f"Invalid XML in {path.relative_to(root)}: {error}")

    article_urls = {urljoin(SITE_URL, url) for url in baseline}
    archive = pages.get(root / "posts/index.html")
    if archive is None:
        errors.append("Writing archive missing at /posts/")
    elif not article_urls.issubset({urljoin(SITE_URL, link) for link in archive.links}):
        errors.append("Writing archive does not link to every historical article")
    for name in ("index.xml", "posts/index.xml"):
        if name not in documents:
            errors.append(f"RSS feed missing or invalid: {name}")
        elif not article_urls.issubset({item.text for item in documents[name].findall("./channel/item/link")}):
            errors.append(f"Historical articles missing from RSS: {name}")
    if "sitemap.xml" not in documents:
        errors.append("Sitemap missing or invalid")
    else:
        sitemap_urls = {loc.text for loc in documents["sitemap.xml"].findall(".//{http://www.sitemaps.org/schemas/sitemap/0.9}loc")}
        if not article_urls.issubset(sitemap_urls):
            errors.append("Historical article URLs missing from sitemap")
    for name in (".nojekyll", "404.html", "robots.txt"):
        if not (root / name).is_file():
            errors.append(f"Required publishing file missing: {name}")

    if errors:
        raise SystemExit("\n".join(errors))
    print(f"Checked {len(pages)} HTML pages: {len(baseline)} historical URLs and their anchors, canonical URLs, local links, images, RSS, and sitemap are intact.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    if not args.destination.is_dir():
        parser.error(f"Build directory does not exist: {args.destination}")
    check_site(args.destination)
