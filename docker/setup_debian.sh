#!/usr/bin/env bash
########################################################################################################################
# Package dependencies
get_apt_deps() {
  llvm_apt_dep="build-essential cmake git python3 libz-dev libxml2-dev ninja-build"
  compas_apt_dep="build-essential cmake git"
  echo "${compas_apt_dep} ${llvm_apt_dep}"
}
setup_env() {
  apt update
  for pkg in "$(get_apt_deps)"
  do
    apt install --no-install-recommends -y ${pkg}
  done
}
########################################################################################################################
# LLVM
fetch_llvm() {
  _home_=${PWD}
  src_dir="${1}"
  build_dir="${2}"
  install_dir="${3}"
  version="${4}"

  llvm_prefix="llvm-project"
  llvm_tag="llvmorg-${version}"
  llvm_url="https://github.com/llvm/llvm-project"

  echo "[fetch] llvm"
  git clone --depth 1 --branch "${llvm_tag}" ${llvm_url}.git ${src_dir}
}
configure_llvm() {
  src_dir="$1"
  build_dir="$2"
  install_dir="$3"
  version="${4}"

  echo "[configure] llvm"
  cmake \
    -G "Ninja" \
    -S "${src_dir}/llvm" \
    -B "${build_dir}" \
    -D "CMAKE_BUILD_TYPE=${ENV_BUILD_CONFIG}" \
    -D "CMAKE_CXX_STANDARD=${ENV_BUILD_CXX_STANDARD}" \
    -D "LLVM_ENABLE_PROJECTS=clang" \
    -D "LLVM_TARGETS_TO_BUILD=RISCV" \
    -D "LLVM_ENABLE_ASSERTIONS=ON" \
    -D "CMAKE_INSTALL_PREFIX=${install_dir}"
}
build_llvm() {
  src_dir="$1"
  build_dir="$2"
  install_dir="$3"
  version="${4}"

  echo "[build] llvm"
  cmake --build "${build_dir}" --parallel "$(nproc)"
  "${build_dir}/bin/clang" --version
}
install_llvm() {
  src_dir="$1"
  build_dir="$2"
  install_dir="$3"
  version="${4}"

  echo "[install] llvm"
  cmake --build "${build_dir}" --parallel "$(nproc)" --target install
  "${install_dir}/bin/clang" --version
}
cleanup_llvm() {
  src_dir="$1"
  build_dir="$2"
  install_dir="$3"
  version="${4}"

  echo "[clean-up] llvm..."
  echo "nothing to do."
  rm -rf "${src_dir}" "${build_dir}"
}
patch_llvm() {
  src_dir="${1}"
  build_dir="${2}"
  install_dir="${3}"
  version="${4}"
  llvm_patches_dir="${5}"

  _home_=${PWD}

  echo "[patch?] llvm ... "
  if [ -f "${llvm_patches_dir}/${llvm_patch_file}" ]; then
    echo "yes. Applying patch: ${llvm_patch_file} from [${llvm_patches_dir}]."
    cd ${src_dir}
    git apply "${llvm_patches_dir}/${llvm_patch_file}"
    cd ${_home_}
  else
    echo "no. Directory ${llvm_patches_dir} does not contain an matching patch file ${llvm_patch_file}. ls <dir>: $(ls "${llvm_patches_dir}")"
  fi
}

setup_compas() {
  compas_src_dir="${1}"
  llvm_src_dir="${2}"

  _home_=${PWD}
  echo "[setup] compas ... "
  cd "${llvm_src_dir}/llvm/lib/Target/RISCV"
  ln -s "${compas_src_dir}" "compas-ft-riscv"
  cd "${_home_}"
}

