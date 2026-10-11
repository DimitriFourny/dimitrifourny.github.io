# Dimitri Fourny — personal website

Hugo sources live in `_hugo/` on `main`. The generated website is published
from the root of `gh-pages`. HTML, copied assets, and Hugo caches do not belong
on `main`.

## Local development

Install **Hugo 0.167.0** (standard edition; no Node.js dependencies):
[official releases](https://github.com/gohugoio/hugo/releases/tag/v0.167.0).

From the repository root:

```sh
hugo server --source _hugo
```

Open <http://localhost:1313/>. The homepage presents the personal portfolio;
`/posts/` contains the complete writing archive.
Profile text and social links are configured in `_hugo/config.toml`.

The homepage pairs selected research with an interactive 2D flow study. Set
`featured: true`, `topic`, and `description` in a post's front matter to feature
it; entries are ordered newest first. The flow runs only on the homepage,
supports pause/resume, stops offscreen and in background tabs, and stays still
with reduced motion. Without JavaScript, an SVG composition remains visible.
The mouse cursor is a circular, impermeable obstacle: flow splits around it even
when held still, with tangential slip at the boundary. Touch gestures scroll
normally rather than controlling the simulation.

Theme CSS and JavaScript live in `_hugo/themes/df0/assets/`. Hugo minifies and
fingerprints them so a returning browser cannot mix old assets with new HTML.
Articles use a quiet, narrow text column with wider code blocks and figures.
The About page's `portrait` front matter places the photo alongside the text on
desktop and centered above it on mobile.

To check a production build:

```sh
hugo --source _hugo --minify --cleanDestinationDir --panicOnWarning
python3 scripts/check_site.py _hugo/public
```

Articles keep their existing `url` front matter, including the `.html` suffix.
Do not change these URLs when editing an old article. The historical URL and
heading-anchor baseline is in `scripts/legacy-posts.json`.

The Firefox and VEH schematics are standalone SVGs in `_hugo/static/img/`.
Edit their labels, connections, and palette in `scripts/generate_diagrams.py`,
then regenerate them with `python3 scripts/generate_diagrams.py`.
Diagrams use graphite surfaces, copper retained-reference arrows, dashed neutral
raw-pointer arrows, and muted red for freed objects. Code fields are monospace;
relationships and labels are preserved across palette updates.
Both the SVG root canvas and its viewBox have a graphite background; article
images must not have a white CSS backing, which can show through at fractional
scaling edges.
Software screenshots retain their original pixels and colors; each caption
links to the original image.

## First deployment and migration

GitHub Pages publishes the generated files from `gh-pages`. Builds and pushes
are performed locally. No custom GitHub workflow or deployment key is needed.
The output includes `.nojekyll` so GitHub serves Hugo's output directly.

For this migration, a `gh-pages` branch with the validated build has also been
prepared locally. Publish it first, then change the Pages source before pushing
the cleanup on `main`:

```sh
git push origin gh-pages
```

In **Settings → Pages**, select **Deploy from a branch**, then **gh-pages** and
**/(root)**. Save and wait for the Pages deployment to finish. This keeps the
site available while generated files are removed from `main`.

After switching the Pages source, push the source changes to `main`:

```sh
git push -u origin main
```

## Publishing updates

Commit source changes on `main`, then build and check the site with the
production commands above. Copy the generated files into a temporary checkout
of `gh-pages`, preserving its Git metadata:

```sh
git fetch origin
pages_checkout="$(mktemp -d "${TMPDIR:-/tmp}/dimitri-pages.XXXXXX")"
git worktree add "$pages_checkout" gh-pages
git -C "$pages_checkout" pull --ff-only origin gh-pages
rsync -a --delete --exclude=.git _hugo/public/ "$pages_checkout/"
git -C "$pages_checkout" add --all
git -C "$pages_checkout" commit -m "Publish website"
git -C "$pages_checkout" push origin gh-pages
git worktree remove "$pages_checkout"
git push origin main
```

Run these commands in order and stop if any command fails. GitHub publishes
the updated branch after the push. Changes pushed only to `main` do not
update the published site. `gh-pages` should contain generated files only.

See [GitHub's publishing-source documentation](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site).
