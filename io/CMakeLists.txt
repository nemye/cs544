set(IO_LIB_SRC
    src/CmdLineParser.cpp
)

add_library(io STATIC ${IO_LIB_SRC})
target_include_directories(io PUBLIC inc)

# Install the lib
install(TARGETS io DESTINATION ${LIB_DIR})