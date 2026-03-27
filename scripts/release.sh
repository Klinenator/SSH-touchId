#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

REMOTE="${REMOTE:-origin}"
BRANCH="${BRANCH:-main}"
DRY_RUN=0
ALLOW_DIRTY=0
SKIP_TESTS=0

usage() {
  cat <<EOF
Usage:
  $0 [--dry-run] [--allow-dirty] [--skip-tests] [--remote <name>] [--branch <name>]

Defaults:
  --remote origin
  --branch main

Examples:
  $0
  $0 --dry-run
  $0 --remote origin --branch main
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --allow-dirty)
      ALLOW_DIRTY=1
      shift
      ;;
    --skip-tests)
      SKIP_TESTS=1
      shift
      ;;
    --remote)
      REMOTE="${2:-}"
      if [[ -z "$REMOTE" ]]; then
        echo "error: --remote requires a value" >&2
        exit 1
      fi
      shift 2
      ;;
    --branch)
      BRANCH="${2:-}"
      if [[ -z "$BRANCH" ]]; then
        echo "error: --branch requires a value" >&2
        exit 1
      fi
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

cd "$PROJECT_ROOT"

if [[ ! -d .git ]]; then
  echo "error: $PROJECT_ROOT is not a git repository" >&2
  exit 1
fi

CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$CURRENT_BRANCH" != "$BRANCH" ]]; then
  echo "error: current branch is '$CURRENT_BRANCH', expected '$BRANCH'" >&2
  echo "hint: switch branches or pass --branch \"$CURRENT_BRANCH\"" >&2
  exit 1
fi

if [[ "$ALLOW_DIRTY" -ne 1 ]] && [[ -n "$(git status --porcelain)" ]]; then
  echo "error: working tree is dirty. commit/stash changes or use --allow-dirty" >&2
  exit 1
fi

git remote get-url "$REMOTE" >/dev/null

if [[ "$SKIP_TESTS" -ne 1 ]]; then
  echo "==> Running tests"
  swift test
else
  echo "==> Skipping tests (--skip-tests)"
fi

echo "==> Ready to push $BRANCH to $REMOTE"

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "==> Dry run enabled"
  git push --dry-run "$REMOTE" "$BRANCH"
  exit 0
fi

git push "$REMOTE" "$BRANCH"
echo "==> Release push complete"
