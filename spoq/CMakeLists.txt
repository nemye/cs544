set(SPOQ_SRC
    test_prog.cpp
)

add_executable(test_prog ${SPOQ_SRC})
target_include_directories(test_prog PRIVATE ${CMAKE_SOURCE_DIR}/msquic/src/inc)
target_link_libraries(test_prog PRIVATE 
    ${CMAKE_SOURCE_DIR}/msquic/artifacts/bin/linux/x64_Release_quictls/libmsquic.a
    numa
    ssl
    crypto
    atomic
    pthread
)

# Install the executable
install(TARGETS test_prog DESTINATION ${INSTALL_DIR})