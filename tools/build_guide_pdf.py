"""Render GUIDE.md as a typeset PDF: pandoc -> HTML -> Chromium print."""

import datetime as dt
import pathlib
import subprocess
import sys

REPO = pathlib.Path("/home/harikishan/KEERTHISHREE/dev/lookout")
HERE = pathlib.Path(__file__).parent
OUT = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else REPO / "Lookout-Complete-Guide.pdf"

TODAY = dt.date.today().strftime("%d %B %Y")
COVER = f"""
<div class="cover">
  <div class="eyebrow">Final year project &middot; Complete guide</div>
  <h1>Lookout</h1>
  <div class="rule"></div>
  <p class="subtitle">AI-powered privileged access misuse and insider threat detection
  for banking, with real-time communication security, a honeypot, and quantum-safe protection.</p>
  <dl>
    <dt>Author</dt><dd>KeerthiShree TS</dd>
    <dt>College</dt><dd>SNS College of Technology</dd>
    <dt>Live demo</dt><dd>https://lookout-9erd.onrender.com</dd>
    <dt>Source code</dt><dd>github.com/keerthishree20/lookout</dd>
    <dt>Date</dt><dd>{TODAY}</dd>
  </dl>
  <p class="note">This guide is self-contained: it explains what the system does, how every part
  works, and why it was built this way, with the real code. All data, employees, customers and
  money in the system are simulated; every measured number in this document comes from that
  synthetic data.</p>
</div>
"""


def prepared_markdown() -> pathlib.Path:
    """The guide, minus its own title block and hand-written contents list:
    the PDF has a cover page and a generated, linked table of contents."""
    text = (REPO / "GUIDE.md").read_text()
    body = text.split("## 1. Overview", 1)
    assert len(body) == 2, "GUIDE.md no longer starts with section 1"
    out = HERE / "guide-body.md"
    out.write_text("## 1. Overview" + body[1])
    return out


def main() -> None:
    cover = HERE / "cover.html"
    cover.write_text(COVER)
    html = HERE / "guide.html"
    source = prepared_markdown()

    subprocess.run(
        [
            "pandoc", str(source),
            "-f", "markdown+pipe_tables+backtick_code_blocks+autolink_bare_uris-smart",
            "-t", "html5", "--standalone",
            "--toc", "--toc-depth=2",
            "--highlight-style=kate",
            "--metadata", "title=Lookout - Complete Project Guide",
            "--css", str(HERE / "guide.css"),
            "--include-before-body", str(cover),
            "-o", str(html),
        ],
        check=True,
    )

    # The cover already carries the title.
    text = html.read_text()
    text = text.replace('<h1 class="title">Lookout - Complete Project Guide</h1>', "")
    text = text.replace('<nav id="TOC" role="doc-toc">', '<nav id="TOC" role="doc-toc"><h1>Contents</h1>')
    # Inline our stylesheet last: pandoc's template emits its own <style> after
    # the linked CSS, and its `pre` rules would otherwise win.
    text = text.replace("</head>", f"<style>{(HERE / 'guide.css').read_text()}</style></head>", 1)
    html.write_text(text)

    from playwright.sync_api import sync_playwright

    footer = (
        '<div style="width:100%;font-family:Helvetica,Arial;font-size:7pt;color:#94a3b8;'
        'padding:0 16mm;display:flex;justify-content:space-between;">'
        "<span>Lookout &middot; Complete Project Guide</span>"
        '<span class="pageNumber"></span></div>'
    )
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page()
        page.goto(html.resolve().as_uri(), wait_until="networkidle")
        page.pdf(
            path=str(OUT),
            format="A4",
            print_background=True,
            display_header_footer=True,
            header_template="<div></div>",
            footer_template=footer,
            margin={"top": "18mm", "bottom": "16mm", "left": "0", "right": "0"},
        )
        browser.close()
    print("wrote", OUT)


if __name__ == "__main__":
    main()
