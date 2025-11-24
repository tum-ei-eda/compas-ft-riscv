####################################################################################################
# Copyright 2025 Chair of EDA, Technical University of Munich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
####################################################################################################
cmake_minimum_required(VERSION 3.14)
####################################################################################################
# cmake project settings
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Default build type to RelWithDebInfo.")
endif()
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED On)
set(CMAKE_CXX_EXTENSIONS OFF)

set(RISCV_ISA "rv64gc")

if(NOT CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/${RISCV_ISA}-toolchain.cmake")
endif()
project(compas_crc LANGUAGES ASM C)
####################################################################################################
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../../cmake")
include("${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/compas.cmake")

add_executable(crc)


compas_source(crc
    SOURCES 
    "${CMAKE_CURRENT_SOURCE_DIR}/main.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/crc.c"
    INCLUDE_DIRS .
    DMR_MOD ${DMR_MOD}
    DMR_FUNCTIONS ${DMR_FUNCTIONS}
    CFP_MOD ${CFP_MOD}
    CFP_FUNCTIONS ${CFP_FUNCTIONS}
)

target_include_directories(crc PUBLIC ".")