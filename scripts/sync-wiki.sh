#!/usr/bin/env bash
# Publish docs/wiki/*.md to the repository's GitHub Wiki (*.wiki.git).
#
# GitHub creates the backing *.wiki.git repository only after the owner creates
# the initial page once in the GitHub UI (Wiki tab -> "Create the first page").
# After that one-time initialization, run this script to publish or refresh all
# version-controlled wiki pages cleanly:
#
#   scripts/sync-wiki.sh                 # publishes docs/wiki to origin's wiki
#   scripts/sync-wiki.sh --dry-run       # renders converted pages without pushing
#   scripts/sync-wiki.sh --branch main   # sets branch used for repo-relative links

set -euo pipefail

DRY_RUN=false
REPO_BRANCH="v1.0"
WIKI_URL=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    --branch)
      REPO_BRANCH="${2:?missing branch name}"
      shift 2
      ;;
    --wiki-url)
      WIKI_URL="${2:?missing wiki remote url}"
      shift 2
      ;;
    -h|--help)
      sed -n '2,12p' "$0"
      exit 0
      ;;
    *)
      echo "sync-wiki: unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

ROOT="$(git rev-parse --show-toplevel)"
SRC_DIR="${ROOT}/docs/wiki"

if [[ ! -d "$SRC_DIR" ]]; then
  echo "sync-wiki: source directory not found: $SRC_DIR" >&2
  exit 1
fi

ORIGIN_URL="$(git -C "$ROOT" remote get-url origin)"
REPO_WEB_URL="${ORIGIN_URL%.git}"
REPO_WEB_URL="${REPO_WEB_URL/#git@github.com:/https://github.com/}"

if [[ -z "$WIKI_URL" ]]; then
  WIKI_URL="${REPO_WEB_URL}.wiki.git"
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

render_pages() {
  local dest="$1"
  local base_blob="${REPO_WEB_URL}/blob/${REPO_BRANCH}"

  for src in "$SRC_DIR"/*.md; do
    local name
    name="$(basename "$src")"
    # Convert repo-relative links (../../file, ../file) to canonical GitHub URLs,
    # and strip .md from sibling wiki links so GitHub Wiki resolves native pages.
    sed -E \
      -e "s|\(\.\./\.\./([^)]+)\)|(${base_blob}/\1)|g" \
      -e "s|\(\.\./([^)]+)\)|(${base_blob}/docs/\1)|g" \
      -e 's|\(([A-Za-z0-9_-]+)\.md(#[^)]*)?\)|(\1\2)|g' \
      "$src" > "${dest}/${name}"
  done
}

if [[ "$DRY_RUN" == true ]]; then
  mkdir -p "${TMP_DIR}/rendered"
  render_pages "${TMP_DIR}/rendered"
  echo "Rendered $(ls -1 "${TMP_DIR}/rendered"/*.md | wc -l) wiki pages for ${WIKI_URL} (branch links -> ${REPO_BRANCH}):"
  ls -1 "${TMP_DIR}/rendered"/*.md
  exit 0
fi

if ! git clone --quiet "$WIKI_URL" "${TMP_DIR}/wiki" 2>/dev/null; then
  cat >&2 <<EOF
sync-wiki: could not clone ${WIKI_URL}

GitHub only initializes the *.wiki.git repository after you click
"Create the first page" once on the repository's Wiki tab:
  ${REPO_WEB_URL}/wiki

After saving that initial placeholder page, re-run:
  scripts/sync-wiki.sh
EOF
  exit 1
fi

# Remove stale pages that were deleted from docs/wiki, then render current pages.
find "${TMP_DIR}/wiki" -maxdepth 1 -type f -name '*.md' -delete
render_pages "${TMP_DIR}/wiki"

cd "${TMP_DIR}/wiki"
git add -A

if git diff --cached --quiet; then
  echo "sync-wiki: GitHub Wiki is already up to date."
  exit 0
fi

git -c user.name="Arman2122" -c user.email="arman.seyri@gmail.com" \
  commit -m "Sync wiki from docs/wiki ($(git -C "$ROOT" rev-parse --short HEAD))"
git push origin HEAD

echo "sync-wiki: published $(ls -1 "${SRC_DIR}"/*.md | wc -l) pages to ${REPO_WEB_URL}/wiki"
