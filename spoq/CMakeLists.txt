
set(SPOQ_SRC
    test_prog.cpp
)

add_executable(test_prog ${SPOQ_SRC})
target_link_libraries(test_prog PRIVATE msquic)

# Install the executable
install(TARGETS test_prog DESTINATION ${INSTALL_DIR})