cmake_minimum_required(VERSION 3.15)
project(ShieldCore VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SOURCES
    ShieldCore.cpp
)

add_executable(ShieldCore WIN32 ${SOURCES})

if (MSVC)
    target_compile_options(ShieldCore PRIVATE /W4 /permissive-)
else()
    target_compile_options(ShieldCore PRIVATE -Wall -Wextra -pedantic)
endif()

target_link_libraries(ShieldCore PRIVATE bcrypt)
