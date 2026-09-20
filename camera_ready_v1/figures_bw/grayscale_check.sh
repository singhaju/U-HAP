#!/usr/bin/env bash
# Grayscale legibility check for camera-ready PDFs.
#
# For each input PDF, renders a per-page color PNG and a per-page grayscale
# PNG side-by-side, so a human reviewer can visually verify nothing becomes
# illegible when the conference proceedings are printed in B&W.
#
# Usage:
#   ./grayscale_check.sh path/to/paper.pdf [path/to/another.pdf ...]
#
# Output:
#   ./bw_check/<basename>_p<N>_color.png
#   ./bw_check/<basename>_p<N>_gray.png
#   ./bw_check/<basename>_p<N>_diff.png   (vertical concat for easy review)
#
# Requires: pdftoppm (poppler-utils), ImageMagick `convert` (optional).

set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <pdf> [<pdf> ...]" >&2
    exit 2
fi

OUT_DIR="$(cd "$(dirname "$0")" && pwd)/bw_check"
mkdir -p "$OUT_DIR"

HAS_CONVERT=0
if command -v convert >/dev/null 2>&1; then
    HAS_CONVERT=1
fi

for pdf in "$@"; do
    if [ ! -f "$pdf" ]; then
        echo "skip: $pdf (not a file)" >&2
        continue
    fi
    base="$(basename "$pdf" .pdf)"
    echo "==> $pdf"

    # Color renders at 200 DPI
    pdftoppm -r 200 "$pdf" "$OUT_DIR/${base}_color" -png

    # Grayscale renders (-gray flag)
    pdftoppm -r 200 -gray "$pdf" "$OUT_DIR/${base}_gray" -png

    # Optional side-by-side diff if ImageMagick is installed
    if [ "$HAS_CONVERT" = "1" ]; then
        for color_png in "$OUT_DIR/${base}_color"-*.png; do
            page="$(basename "$color_png" .png | sed "s/${base}_color-//")"
            gray_png="$OUT_DIR/${base}_gray-${page}.png"
            if [ -f "$gray_png" ]; then
                convert "$color_png" "$gray_png" +append \
                    "$OUT_DIR/${base}_p${page}_diff.png"
            fi
        done
        echo "    side-by-side diffs: $OUT_DIR/${base}_p*_diff.png"
    else
        echo "    (install ImageMagick for side-by-side diffs)"
    fi

    echo "    color/gray PNGs: $OUT_DIR/${base}_{color,gray}-*.png"
done

echo
echo "Open the *_diff.png (or color vs gray pairs) and check:"
echo "  - all figure text remains readable in grayscale"
echo "  - all line/marker styles remain distinguishable"
echo "  - no color-only encoded information (red vs green) is lost"
