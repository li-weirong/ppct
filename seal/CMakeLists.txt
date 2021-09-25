cmake_minimum_required(VERSION 3.12)
project(SEALDemo LANGUAGES CXX)
find_package(SEAL 3.6.4 EXACT REQUIRED)
add_executable(client-setup)
target_sources(client-setup
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/client-setup.cpp
)
target_link_libraries(client-setup PRIVATE SEAL::seal)
add_executable(server-compute)
target_sources(server-compute
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/server-compute.cpp
)
target_link_libraries(server-compute PRIVATE SEAL::seal)
add_executable(client-decrypt)
target_sources(client-decrypt
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/client-decrypt.cpp
)
target_link_libraries(client-decrypt PRIVATE SEAL::seal)
add_executable(demo)
target_sources(demo
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/demo.cpp
)
target_link_libraries(demo PRIVATE SEAL::seal)