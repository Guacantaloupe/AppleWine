cmake_minimum_required(VERSION 3.20)

project(AppleWine VERSION 0.1.0 LANGUAGES CXX)

add_executable(AppleWine WIN32 AppleWine.cpp)

target_compile_features(AppleWine PRIVATE cxx_std_17)
target_compile_definitions(AppleWine PRIVATE
    UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN
)
target_link_libraries(AppleWine PRIVATE Ole32 OleAut32 Comdlg32 User32)

if(MSVC)
    target_compile_options(AppleWine PRIVATE /W4 /EHsc)
    set_property(TARGET AppleWine PROPERTY MSVC_RUNTIME_LIBRARY
        "MultiThreaded$<$<CONFIG:Debug>:Debug>")
else()
    target_compile_options(AppleWine PRIVATE -Wall -Wextra -Wpedantic)
endif()

set_target_properties(AppleWine PROPERTIES
    CXX_EXTENSIONS OFF
    OUTPUT_NAME "AppleWine"
)
