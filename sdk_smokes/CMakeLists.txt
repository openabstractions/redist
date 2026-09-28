cmake_minimum_required(VERSION 3.16)
project(openabstractions_installed_sdk_smokes LANGUAGES CXX)

find_package(abstraction_facade_resolution CONFIG REQUIRED)
find_package(abstraction_config CONFIG REQUIRED)

add_executable(cpp_probe cpp_probe.cpp)
target_compile_features(cpp_probe PRIVATE cxx_std_17)
target_link_libraries(cpp_probe PRIVATE abstraction::facade_resolution abstraction::config_client)
