# Project information
cmake_minimum_required(VERSION 3.16)
project(CS544
    VERSION 0.0.1
    DESCRIPTION "CS544 project for SPOQ"
    LANGUAGES CXX)


# Generic CMake setup ----------------------------------------------------------------------------------
if (NOT CMAKE_BUILD_TYPE)
    message(STATUS "Using default RELEASE build.")
    set(CMAKE_BUILD_TYPE)
endif()

# Set the C++ compiler
set(CMAKE_CXX_COMPILER "g++")

# Set the C++ standard to C++20
set(CMAKE_CXX_STANDARD              20)
set(CMAKE_CXX_STANDARD_REQUIRED     ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Set flags for each build type
set(DEBUG_FLAGS                    "-g -ggdb")
set(CMAKE_CXX_FLAGS_DEBUG          "-g -ggdb ${DEBUG_FLAGS}")
#set(CMAKE_CXX_FLAGS_DEBUG          "-g ${DEBUG_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
set(CMAKE_CXX_FLAGS_RELEASE        "-O3")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 ${DEBUG_FLAGS}")
#set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s")

# Warnings
set(GCC_WARNINGS
    -Wall
    -Wextra # reasonable and standard
    # -Wshadow # warn the user if a variable declaration shadows one from a parent context
    # -Wcast-align # warn for potential performance problem casts
    # -Wconversion # warn on type conversions that may lose data
    # -Wno-sign-conversion # warn on sign conversions
    # -Wunused # warn on anything being unused
    # -Wmisleading-indentation # warn if indentation implies blocks where blocks do not exist
    # -Wduplicated-cond # warn if if / else chain has duplicated conditions
    # -Wlogical-op # warn about logical operations being used where bitwise were probably wanted
    # -Wformat=2 # warn on security issues around functions that format output (ie printf)
)

# Add warnings to the compiler flags
list(APPEND CLANG_WARNINGS -Werror)
list(APPEND GCC_WARNINGS)
set(PROJECT_WARNINGS_CXX ${GCC_WARNINGS})
set(PROJECT_WARNINGS_C "${PROJECT_WARNINGS_CXX}")
string(REPLACE ";" " " WARNING_STRING "${PROJECT_WARNINGS_CXX}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${WARNING_STRING}")
string(REPLACE ";" " " WARNING_STRING "${PROJECT_WARNINGS_CXX}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${WARNING_STRING}")

#--------------------------------------------------------------------------------------------------

# Project specific subdirectories and includes below this point

# Add msquic include path
include_directories(msquic/src/inc)

# Link against msquic static library
link_directories(msquic/artifacts/bin/linux/x64_Release_quictls)

# Set subdirectories with more CMakeLists.txt
add_subdirectory(io)
add_subdirectory(spoq)

# Set installation directory
set(INSTALL_DIR "${CMAKE_SOURCE_DIR}/bin")
set(LIB_DIR "${CMAKE_SOURCE_DIR}/lib")
