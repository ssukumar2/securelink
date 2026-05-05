#!/usr/bin/env bash
# Format all C/C++ sources in the project.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

if ! command -v clang-format >/dev/null 2>&1; then
    echo "error: clang-format not installed" >&2
    exit 1
fi

mapfile -t FILES < <(git ls-files '*.c' '*.h' '*.cpp' '*.hpp')

if [[ ${#FILES[@]} -eq 0 ]]; then
    echo "no source files found"
    exit 0
fi

echo "formatting ${#FILES[@]} file(s)..."
clang-format -i --style=file "${FILES[@]}"
echo "done."
