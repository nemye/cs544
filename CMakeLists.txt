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
set(CMAKE_CXX_FLAGS_RELEASE        "-O3")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 ${DEBUG_FLAGS}")

# Warnings
set(GCC_WARNINGS
    -Wall
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

# Project specific subdirectories and includes below this point
#--------------------------------------------------------------------------------------------------

# Specify root directory to link against msquic (static) library
set(MSQUIC_DIR ${CMAKE_SOURCE_DIR}/msquic)

# Set subdirectories with more CMakeLists.txt
add_subdirectory(spoq)

# Set installation directories
set(INSTALL_DIR "${CMAKE_SOURCE_DIR}/bin")
