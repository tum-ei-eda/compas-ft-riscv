if (NOT COMPAS_LLVM_ROOT)
    if (DEFINED ENV{COMPAS_LLVM_ROOT})
        set(COMPAS_LLVM_ROOT "$ENV{COMPAS_LLVM_ROOT}" CACHE PATH "COMPAS_LLVM_ROOT")
    else()
        message(FATAL_ERROR "Need to set COMPAS_LLVM_ROOT to valid LLVM with CompaS(eC) patches")
    endif()
endif()

message(STATUS "LLVM_DIR: ${COMPAS_LLVM_ROOT}")
find_package(LLVM REQUIRED CONFIG
    NO_DEFAULT_PATH
    NO_SYSTEM_ENVIRONMENT_PATH
    PATHS ${COMPAS_LLVM_ROOT}/lib/cmake/llvm
)
message(STATUS "LLVM_DIR: ${LLVM_DIR}")
set(CLANG_INCLUDE_DIRS ${COMPAS_LLVM_ROOT}/lib/clang/${LLVM_VERSION}/include)
if(NOT CMAKE_SYSTEM_PROCESSOR)
    message(WARNING "CMAKE_SYSTEM_PROCESSOR not specified. Default to ${CMAKE_SYSTEM_PROCESSOR}.")
    set(CMAKE_SYSTEM_PROCESSOR riscv64)
endif()

# \brief Run a set of SOURCES through clang+llc (with compas software implemented hardware fault tolerance COMPAS) techniques
# \details Do not add the SOURCES directly to the target, but call compas_source(). This CMake function will generate hardened
#          assembly files and add these to the given TARGET
# \params FINE_GRAINED[OPTION], if set fine grained scheduling will be applied to the DMR technique
#         DMR_MOD [SINGLE VAL] {NZDC, NZDC+NEMESIS, NZDC+NEMESEC}, if specified its value will be passed as the dual module redundancy protection technique to LLC
#         CFP_MOD [SINGLE VAL] {CFCSS, RASM}, if specified its value will be passed as the control flow protection technique to LLC
#         DMR_FUNCTIONS [MULTI VAL], May contain a list of function names (symbolic names) that the DMR technique shall be applied to
#         CFP_FUNCTIONS [MULTI VAL], May contain a list of function names (symbolic names) that the CFP technique shall be applied to
#         SOURCES [MULTI VAL], List of C and C++ sources that shall pass through clang+llc instead of direct listing within CMake
#         INCLUDE_DIRS [MULTI VAL], Additional include directories for clang+llc flow
function(compas_source TARGET)
    set(foptions FINE_GRAINED)
    set(foneValueArgs DMR_MOD CFP_MOD OPT)
    set(fmultiValueArgs DMR_FUNCTIONS CFP_FUNCTIONS SOURCES INCLUDE_DIRS COMPILE_DEFINITIONS)
    cmake_parse_arguments(COMPAS "${foptions}" "${foneValueArgs}" "${fmultiValueArgs}" ${ARGN})

    find_program(COMPAS_CLANG NAMES clang
        HINTS ${COMPAS_LLVM_ROOT}/bin
        ENV COMPAS_LLVM_ROOT
        NO_CMAKE_PATH NO_CMAKE_ENVIRONMENT_PATH NO_CMAKE_SYSTEM_PATH
    )

    find_program(COMPAS_LLC NAMES llc
        HINTS ${COMPAS_LLVM_ROOT}/bin
        ENV COMPAS_LLVM_ROOT
        NO_CMAKE_PATH NO_CMAKE_ENVIRONMENT_PATH NO_CMAKE_SYSTEM_PATH
    )

    if(CMAKE_C_FLAGS_RELEASE)
        set(CMAKE_C_FLAGS_RELEASE_old ${CMAKE_C_FLAGS_RELEASE})
        string(REPLACE "-O3" "-O2" CMAKE_C_FLAGS_RELEASE ${CMAKE_C_FLAGS_RELEASE})
        message(WARNING "{compas_source}: Release, aka -O3, not supported because of LTOs. Replacing CMAKE_CXX_FLAGS_RELEASE \"${CMAKE_C_FLAGS_RELEASE_old}\" with \"${CMAKE_C_FLAGS_RELEASE}\".")
    endif()

    if(CMAKE_CXX_FLAGS_RELEASE)
        set(CMAKE_CXX_FLAGS_RELEASE_old ${CMAKE_CXX_FLAGS_RELEASE})
        string(REPLACE "-O3" "-O2" CMAKE_CXX_FLAGS_RELEASE ${CMAKE_CXX_FLAGS_RELEASE})
        message(WARNING "{compas_source}: Release, aka -O3, not supported because of LTOs. Replacing CMAKE_CXX_FLAGS_RELEASE \"${CMAKE_CXX_FLAGS_RELEASE_old}\" with \"${CMAKE_CXX_FLAGS_RELEASE}\".")
    endif()

    get_target_property(BINARY_DIR "${TARGET}" BINARY_DIR)
    get_target_property(TARGET_NAME "${TARGET}" NAME)
    #get_target_property(TARGET_COMPILE_OPTIONS "${TARGET}" COMPILE_OPTIONS)

    # this yields the /path/to/cross-tc/bin
    file(TO_NATIVE_PATH "${CMAKE_C_COMPILER}" PATH_TO_C_COMPILER)
    string(REGEX REPLACE "\/[^\/]*$" "" PATH_TO_C_COMPILER ${PATH_TO_C_COMPILER})

    #if(NOT COMPAS_INCLUDE_DIRS)
    get_target_property(INCLUDE_DIRS_ARG "${TARGET}" INCLUDE_DIRECTORIES)
    set(INCLUDE_DIRS_ARG ${INCLUDE_DIRS_ARG} ${COMPAS_INCLUDE_DIRS}
        "${PATH_TO_C_COMPILER}/../${CMAKE_SYSTEM_PROCESSOR}-unknown-elf/include"
    )

    list(TRANSFORM INCLUDE_DIRS_ARG PREPEND "-I")
    #endif()

    # make arguments REQUIRED
    if(NOT COMPAS_SOURCES)
        message(FATAL_ERROR "{compas_source}: Need to specify a source file list compas_source(SOURCES ... )")
    else()
        set(COMPAS_CLANG_OUT ${COMPAS_SOURCES})
        list(TRANSFORM COMPAS_CLANG_OUT REPLACE ".c$" ".ll")
        list(TRANSFORM COMPAS_CLANG_OUT REPLACE ".cpp$" ".ll")
        list(TRANSFORM COMPAS_CLANG_OUT REPLACE ".cc$" ".ll")
        list(TRANSFORM COMPAS_CLANG_OUT REPLACE "[^\/]*\/" "")

        set(COMPAS_LLC_OUT ${COMPAS_CLANG_OUT})
        list(TRANSFORM COMPAS_LLC_OUT REPLACE ".ll$" ".S")
    endif()

    # generate IR sources from given C-Sources
    if(${CMAKE_BUILD_TYPE} MATCHES "[rR]elease|RELEASE")
        set(COMPAS_OPT_FLAG "-O3")
    else()
        if(${CMAKE_BUILD_TYPE} MATCHES "[dD]ebug|DEBUG")
            set(COMPAS_OPT_FLAG "-O0")
        else()
            set(COMPAS_OPT_FLAG "-O2")
        endif()
    endif()
    string(REGEX REPLACE " " ";" COMPAS_C_FLAGS "${CMAKE_C_FLAGS}")

    if("${CMAKE_SYSTEM_PROCESSOR}" MATCHES "rv64")
        set(LLC_MARCH "riscv64")
    elseif("${CMAKE_SYSTEM_PROCESSOR}" MATCHES "rv32")
        set(LLC_MARCH "riscv32")
    else()
        set(LLC_MARCH "${CMAKE_SYSTEM_PROCESSOR}")
    endif()

    set(CLANG_ARGS 
        -emit-llvm -S
        --target=${LLC_MARCH}
        ${COMPAS_OPT_FLAG}
        ${COMPAS_C_FLAGS}
        #-fno-inline-functions
        #-masm=riscv32
        -fno-jump-tables # we need this unfortunately, because we do not support signature monitoring for jump tables in RISCV (indirect jump based)
        -nostdlib
        -DCOMPAS_ACTIVE
        ${COMPAS_COMPILE_DEFINITIONS}
        ${INCLUDE_DIRS_ARG} -isystem "${PATH_TO_C_COMPILER}/../${RISCV_TOOLCHAIN_BASENAME}/include"
    )
    add_custom_command(
        OUTPUT ${COMPAS_CLANG_OUT}
        DEPENDS ${SOURCES}
        COMMAND ${COMPAS_CLANG} ${CLANG_ARGS} ${COMPAS_SOURCES}
        COMMENT "{compas_source}: executing\n... ${COMPAS_CLANG} ${CLANG_ARGS} ${COMPAS_SOURCES}"
        VERBATIM
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )

    if(COMPAS_DMR_MOD)
        # format function names for dual module redundancy technique
        list(JOIN COMPAS_DMR_FUNCTIONS "," DMR_FUNCTIONS)
        set(DMR_ARG "-${COMPAS_DMR_MOD}=${DMR_FUNCTIONS}")
    endif()
    if(COMPAS_CFP_MOD)
        # format function names for control flow protection technique
        list(JOIN COMPAS_CFP_FUNCTIONS "," CFP_FUNCTIONS)
        set(CFP_ARG "-${COMPAS_CFP_MOD}=${CFP_FUNCTIONS}")
    endif()

    if(COMPAS_FINE_GRAINED)
        set(FINE_GRAINED "-FGS")
    endif()

    set(LLC_MATTR "")
    string(REGEX REPLACE "rv[0-9]+" "" ISA_STR ${RISCV_ISA})
    string(REGEX REPLACE "^g" "imafd" ISA_STR ${ISA_STR})
    string(REGEX REPLACE "_.*" "" ISA_STR ${ISA_STR})
    string(LENGTH ${ISA_STR} ISA_STR_LEN)
    MATH(EXPR ISA_STR_RANGE "${ISA_STR_LEN}-1") # we do not want the 0..N but 0..N-1
    foreach(CHARIDX RANGE ${ISA_STR_RANGE})
        string(SUBSTRING ${ISA_STR} ${CHARIDX} 1 CHAR)
        if(NOT ${CHAR} STREQUAL "i")
            string(APPEND LLC_MATTR "+${CHAR}")
            if(NOT ${CHARIDX} EQUAL ${ISA_STR_RANGE})
                string(APPEND LLC_MATTR ",")
            endif()
        endif()
    endforeach()
    if(NOT ${LLC_MATTR} STREQUAL "")
        string(PREPEND LLC_MATTR "-mattr=")
    endif()

    # harden and statically link IR to assembly sources
    foreach(LLVM_SRC IN LISTS COMPAS_CLANG_OUT)
        set(LLC_OUT ${LLVM_SRC})
        list(TRANSFORM LLC_OUT REPLACE ".ll$" ".S")
        message("{compas_source}: Generating ${LLC_OUT} from ${LLVM_SRC}")
        set(LLC_CMD ${COMPAS_LLC}
            ${COMPAS_OPT_FLAG} -march=${LLC_MARCH} ${LLC_MATTR}
            ${FINE_GRAINED} ${DMR_ARG} ${CFP_ARG}
            ${LLVM_SRC} -o ${LLC_OUT})
        add_custom_command(
            OUTPUT ${LLC_OUT}
            DEPENDS ${LLVM_SRC}
            COMMAND ${LLC_CMD}
            COMMENT "{compas_source}: executing\n... ${LLC_CMD}"
            WORKING_DIRECTORY ${BINARY_DIR}
        )
        # add the generated assembly file as a source *instead* of the C/C++ source
        target_sources(${TARGET}  PRIVATE ${LLC_OUT})
    endforeach()
endfunction()
