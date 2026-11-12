#!/bin/sh
# Build the project landing page and PDF/HTML manual without modifying sources.
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
site_dir="$repo_dir/docs/site"

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

cp -R "$site_dir/." "$output_dir/"
sed -e "s|{{VERSION}}|$version|g" \
    -e "s|{{MANUAL_PDF}}|$document_name.pdf|g" \
    -e 's|{{SOURCE_URL}}|https://github.com/tum-ei-eda/compas-ft-riscv|g' \
    "$site_dir/index.html" > "$output_dir/index.html"
mkdir -p "$output_dir/assets" "$output_dir/manual"
cp "$manual_dir/src/figs/compas.svg" "$output_dir/assets/compas.svg"
cp "$manual_dir/manual.css" "$output_dir/assets/manual.css"

# Browsers display PNG figures directly, including on devices without PDF embeds.
mkdir -p "$output_dir/figs"
for figure in figs/*.pdf; do
    pdftoppm -singlefile -png -scale-to 1600 \
        "$figure" "$output_dir/${figure%.pdf}"
done

# Keep existing versioned HTML/PDF URLs, and provide a stable /manual/ route.
# Each HTML file resolves images and navigation relative to its own directory.
render_manual() {
    manual_output=$1
    asset_prefix=$2
    pandoc main.tex --from=latex --to=html5 --standalone --toc \
        --shift-heading-level-by=1 --toc-depth=5 \
        --citeproc --bibliography=references.bib \
        --lua-filter="$manual_dir/html.lua" \
        --template="$manual_dir/template.html" \
        --metadata=lang:en --metadata="title:COMPAS manual" \
        --metadata="figure-prefix:$asset_prefix" \
        --variable="asset-prefix:$asset_prefix" \
        --variable="compas-version:$version" \
        --variable="pdf-url:$asset_prefix$document_name.pdf" \
        --variable="home-url:${asset_prefix}index.html" \
        --output="$manual_output"
}
render_manual "$output_dir/$document_name.html" ""
render_manual "$output_dir/manual/index.html" "../"
printf 'Project site written to %s\n' "$output_dir"
