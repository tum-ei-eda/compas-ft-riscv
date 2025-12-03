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
get_testenv_apt_deps() {
  spike_apt_dep="wget tar device-tree-compiler libboost-regex-dev libboost-system-dev"
  base_apt_dep="$(get_apt_deps)"
  echo "${base_apt_dep} ${spike_apt_dep}"
}
setup_testenv() {
  apt update
  for pkg in "$(get_testenv_apt_deps)"
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
  llvm_ref="${version}"
  llvm_url="https://github.com/llvm/llvm-project"

  echo "[fetch] llvm"
  git clone --depth 1 --branch "${llvm_ref}" ${llvm_url}.git ${src_dir}
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
  #cmake --build "${build_dir}" --parallel "$(nproc)" --target clang
  "${build_dir}/bin/clang" --version
  #cmake --build "${build_dir}" --parallel "$(nproc)" --target llc
  "${build_dir}/bin/llc" --version
}
install_llvm() {
  src_dir="$1"
  build_dir="$2"
  install_dir="$3"
  version="${4}"

  echo "[install] llvm"
  cmake --build "${build_dir}" --parallel "$(nproc)" --target install
  #cmake --install "${build_dir}" --component clang
  "${install_dir}/bin/clang" --version
  #cmake --install "${build_dir}" --component llc
  "${install_dir}/bin/llc" --version
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
  version="${4#*-}"
  llvm_patches_dir="${5}"
  llvm_patch_file="llvm${version}_src.patch"
  _home_=${PWD}

  echo "[patch?] llvm ... "
  if [ -f "${llvm_patches_dir}/${llvm_patch_file}" ]; then
    echo "yes. Applying patch: ${llvm_patch_file} from [${llvm_patches_dir}]."
    cd ${src_dir}
    git apply "${llvm_patches_dir}/${llvm_patch_file}"
    cd ${_home_}
  else
    echo "no. Directory ${llvm_patches_dir} does not contain an matching patch file ${llvm_patch_file}. ls <dir>: $(ls "${llvm_patches_dir}")"
    return 1
  fi
  echo "[patch?] llvm for gcc>=13... "
  llvm_patch_file="gccGTE13.llvmorg-${version}.patch"
  if [ -f "${llvm_patches_dir}/${llvm_patch_file}" ]; then
    echo "yes. Applying patch: ${llvm_patch_file} from [${llvm_patches_dir}]."
    cd ${src_dir}
    git apply "${llvm_patches_dir}/${llvm_patch_file}"
    cd ${_home_}
  else
    echo "no. Directory ${llvm_patches_dir} does not contain an matching patch file ${llvm_patch_file}. ls <dir>: $(ls "${llvm_patches_dir}")"
  fi

  return 0
}
setup_compas() {
  compas_src_dir="${1}"
  llvm_src_dir="${2}"

  _home_=${PWD}
  echo "[setup] compas ... "
  cd "${llvm_src_dir}/llvm/lib/Target/RISCV"
  ln -s "${compas_src_dir}" "compas-ft-riscv"
  ls -la .
  cd "${_home_}"
}
########################################################################################################################
# RISC-V GNU Toolchain
fetch_rvgnu() {
  _home_=${PWD}
  rvgnu_dir="$1"
  url="$2"
  target_name="$3"

  echo "[fetch] risc-v gnu tools"
  wget "${url}" -q --output-document="${target_name}-linux-x64.tar.gz"
  tar xf "${target_name}-linux-x64.tar.gz"
  mv "${target_name}" "${rvgnu_dir}"
  rm "${target_name}-linux-x64.tar.gz"

  spike_ref="88edb8b81383bf282949be30476c9e4d5459cec4"
  spike_url="https://github.com/riscv-software-src/riscv-isa-sim"
  git clone ${spike_url}.git /spike-src
  cd /spike-src
  git checkout ${spike_ref}
  cd ${_home_}

  pk_ref="9c61d29846d8521d9487a57739330f9682d5b542"
  pk_url="https://github.com/riscv-software-src/riscv-pk"
  git clone ${pk_url}.git /pk-src
  cd /pk-src
  git checkout ${pk_ref}

  cd ${_home_}

}
configure_rvgnu() {
  _home_=${PWD}
  rvgnu_dir="$1"

  echo "[configure] risc-v gnu tools"
  export RISCV="${rvgnu_dir}"
  export PATH="${RISCV}/bin:${PATH}"

  mkdir -p /spike-src/build && cd /spike-src/build
  ../configure --prefix=${RISCV}

  mkdir -p /pk-src/build && cd /pk-src/build
  ../configure --prefix=$RISCV --host=riscv-none-elf --with-arch=rv64imafdc_zicsr_zifencei
  make -j $(nproc)
  make install

  cd ${_home_}
}
build_rvgnu() {
  echo "[build] risc-v gnu tools"
  make -C /pk-src/build -j $(nproc)
  make -C /spike-src/build -j $(nproc)
}
install_rvgnu() {
  echo "[install] risc-v gnu tools"
  make -C /pk-src/build  install
  make -C /spike-src/build  install
}
cleanup_rvgnu() {
  echo "[clean-up] risc-v gnu tools"
  rm -rf "/spike-src/" "/pk-src/"
}