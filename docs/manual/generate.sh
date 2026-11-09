#!/bin/sh
# Build the PDF manual and Pages directory without modifying the sources.
set -eu

manual_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$manual_dir/../.." && pwd)
output_dir=${1:-"$repo_dir/build/manual/site"}
version=$(sed -n 's/^ENV_COMPAS_VERSION=//p' "$repo_dir/docker/.env")
case "$version" in
    ''|*[!A-Za-z0-9.+-]*)
        echo "Missing or invalid ENV_COMPAS_VERSION in docker/.env" >&2
        exit 1
        ;;
esac
document_name="compas-ft-riscv_v${version}_manual"

mkdir -p "$output_dir"
output_dir=$(CDPATH= cd -- "$output_dir" && pwd)
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
cp -R "$manual_dir/src" "$work_dir/src"
cd "$work_dir/src"
sed -i "s/@VERSION@/$version/g" main.tex

# latexmk runs BibTeX and repeats LaTeX until citations and references resolve.
latexmk -pdf -interaction=nonstopmode -halt-on-error \
    -outdir="$work_dir/latex" main.tex
cp "$work_dir/latex/main.pdf" "$output_dir/$document_name.pdf"

# Browsers display PNG figures directly, including on devices without PDF embeds.
mkdir -p "$output_dir/figs"
for figure in figs/*.pdf; do
    pdftoppm -singlefile -png -scale-to 1600 \
        "$figure" "$output_dir/${figure%.pdf}"
done
printf '<p><a href="%s.pdf">Download the PDF manual (version %s)</a></p>\n' \
    "$document_name" "$version" > "$work_dir/download.html"
pandoc main.tex --from=latex --to=html5 --standalone --toc \
    --citeproc --bibliography=references.bib \
    --lua-filter="$manual_dir/html.lua" \
    --metadata=lang:en --metadata="title:COMPAS-FT-RISCV Manual (version $version)" \
    --include-before-body="$work_dir/download.html" \
    --output="$output_dir/$document_name.html"
cp "$output_dir/$document_name.html" "$output_dir/index.html"
printf 'Manual site written to %s\n' "$output_dir"
