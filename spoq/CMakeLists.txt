set(SPOQ_CLIENT_SRC
    src/spoq_client.cpp
)

set(SPOQ_SERVER_SRC
    src/spoq_server.cpp
)

add_executable(spoq_client ${SPOQ_CLIENT_SRC})
target_include_directories(spoq_client PRIVATE ${CMAKE_SOURCE_DIR}/msquic/src/inc ${CMAKE_SOURCE_DIR}/spoq/inc)
target_link_libraries(spoq_client PRIVATE 
    ${CMAKE_SOURCE_DIR}/msquic/artifacts/bin/linux/x64_Release_quictls/libmsquic.a
    numa
    ssl
    crypto
    atomic
    pthread
)

add_executable(spoq_server ${SPOQ_SERVER_SRC})
target_include_directories(spoq_server PRIVATE ${MSQUIC_DIR}/src/inc ${CMAKE_SOURCE_DIR}/spoq/inc)
target_link_libraries(spoq_server PRIVATE 
    ${MSQUIC_DIR}/artifacts/bin/linux/x64_Release_quictls/libmsquic.a
    numa
    ssl
    crypto
    atomic
    pthread
)

# Install the executable
install(TARGETS spoq_client spoq_server DESTINATION ${INSTALL_DIR})