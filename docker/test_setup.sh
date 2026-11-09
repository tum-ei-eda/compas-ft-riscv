#!/bin/sh
# Exercise the Docker setup helpers without downloading or building LLVM.
set -eu

test_script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
. "$test_script_dir/setup_debian.sh"
test_root=$(mktemp -d "${TMPDIR:-/tmp}/compas-docker-setup.XXXXXX")
trap 'rm -rf "$test_root"' 0
trap 'exit 1' HUP INT TERM

fail() {
  printf '%s\n' "$*" >&2
  exit 1
}

expect_failure() {
  if ( "$@" ) > "$test_root/failure.log" 2>&1; then
    cat "$test_root/failure.log" >&2
    fail "Expected failure: $*"
  fi
}

# Generate actual Git patches against two independent files.
git init -q "$test_root/template"
printf 'before\n' > "$test_root/template/required.txt"
printf 'before\n' > "$test_root/template/optional.txt"
git -C "$test_root/template" add required.txt optional.txt
printf 'patched\n' > "$test_root/template/required.txt"
git -C "$test_root/template" diff -- required.txt > "$test_root/required.patch"
printf 'patched\n' > "$test_root/template/optional.txt"
git -C "$test_root/template" diff -- optional.txt > "$test_root/optional.patch"
printf 'before\n' > "$test_root/template/required.txt"
printf 'before\n' > "$test_root/template/optional.txt"

new_case() {
  test_case_dir="$test_root/$1"
  mkdir -p "$test_case_dir/patch files"
  cp -R "$test_root/template" "$test_case_dir/llvm tree"
  cp "$test_root/required.patch" "$test_case_dir/patch files/llvm16.0.6_src.patch"
}

new_case relative
(
  cd "$test_case_dir"
  patch_llvm "llvm tree" build install llvmorg-16.0.6 "patch files"
  test "$PWD" = "$test_case_dir" || fail 'patch_llvm changed the working directory'
  test "$(cat 'llvm tree/required.txt')" = patched || fail 'Relative patch was not applied'
  test "$(cat 'llvm tree/optional.txt')" = before || fail 'Missing optional patch changed the source'
)

new_case absolute
cp "$test_root/optional.patch" "$test_case_dir/patch files/gccGTE13.llvmorg-16.0.6.patch"
patch_llvm "$test_case_dir/llvm tree" build install llvmorg-16.0.6 "$test_case_dir/patch files"
test "$(cat "$test_case_dir/llvm tree/required.txt")" = patched || fail 'Absolute patch was not applied'
test "$(cat "$test_case_dir/llvm tree/optional.txt")" = patched || fail 'Optional patch was not applied'

new_case missing_argument
expect_failure patch_llvm "$test_case_dir/llvm tree" build install llvmorg-16.0.6
expect_failure patch_llvm "$test_case_dir/llvm tree" build install llvmorg-16.0.6 ""

new_case missing
rm "$test_case_dir/patch files/llvm16.0.6_src.patch"
expect_failure patch_llvm "$test_case_dir/llvm tree" build install llvmorg-16.0.6 "$test_case_dir/patch files"

new_case invalid
printf 'invalid patch\n' > "$test_case_dir/patch files/llvm16.0.6_src.patch"
expect_failure patch_llvm "$test_case_dir/llvm tree" build install llvmorg-16.0.6 "$test_case_dir/patch files"

new_case invalid_optional
printf 'invalid patch\n' > "$test_case_dir/patch files/gccGTE13.llvmorg-16.0.6.patch"
expect_failure patch_llvm "$test_case_dir/llvm tree" build install llvmorg-16.0.6 "$test_case_dir/patch files"

new_case symlink
mkdir -p "$test_case_dir/compas-ft-riscv" "$test_case_dir/llvm tree/llvm/lib/Target/RISCV"
printf '# COMPAS fixture\n' > "$test_case_dir/compas-ft-riscv/CMakeLists.txt"
(
  cd "$test_case_dir"
  setup_compas compas-ft-riscv "llvm tree"
  test "$PWD" = "$test_case_dir" || fail 'setup_compas changed the working directory'
  test_link='llvm tree/llvm/lib/Target/RISCV/compas-ft-riscv'
  test -L "$test_link" || fail 'COMPAS symlink was not created'
  test -f "$test_link/CMakeLists.txt" || fail 'COMPAS symlink does not resolve to the source'
  test "$(CDPATH= cd "$test_link" && pwd -P)" = "$test_case_dir/compas-ft-riscv" || fail 'COMPAS symlink targets the wrong source'
)
test_existing_target="$test_case_dir/llvm tree/llvm/lib/Target/RISCV/compas-ft-riscv"
rm "$test_existing_target"
printf 'occupied\n' > "$test_existing_target"
expect_failure setup_compas "$test_case_dir/compas-ft-riscv" "$test_case_dir/llvm tree"

printf 'Docker setup helper tests passed.\n'
