cmake_minimum_required(VERSION 3.0.0)
project(SERVER VERSION 0.1.0)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
link_libraries(crypto)
link_libraries(ssl)
link_directories(${PROJECT_SOURCE_DIR}/lib)

add_executable(SERVER ../src/tcp_server.c)
#add_executable(SERVER ../src/SERVER_.c)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})

