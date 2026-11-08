# Cross-platform build of the ANTA capture engine (macOS, Linux, Windows).
#   cmake -B build/cmake -DCMAKE_BUILD_TYPE=Release && cmake --build build/cmake --config Release
# Windows needs the Npcap SDK: -DNPCAP_SDK=C:/path/to/npcap-sdk (or the NPCAP_SDK env var).
cmake_minimum_required(VERSION 3.16)
project(anta_engine LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

file(GLOB ENGINE_SOURCES CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/engine/src/*.cpp)
add_executable(anta-engine ${ENGINE_SOURCES})

find_package(Threads REQUIRED)
target_link_libraries(anta-engine PRIVATE Threads::Threads)

if(WIN32)
  if(NOT NPCAP_SDK)
    set(NPCAP_SDK $ENV{NPCAP_SDK})
  endif()
  if(NOT NPCAP_SDK)
    message(FATAL_ERROR "Set NPCAP_SDK to the extracted Npcap SDK (https://npcap.com/#download)")
  endif()
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(NPCAP_LIBDIR ${NPCAP_SDK}/Lib/x64)
  else()
    set(NPCAP_LIBDIR ${NPCAP_SDK}/Lib)
  endif()
  target_include_directories(anta-engine PRIVATE ${NPCAP_SDK}/Include)
  target_link_libraries(anta-engine PRIVATE ${NPCAP_LIBDIR}/wpcap.lib ws2_32 delayimp)
  # wpcap.dll lives in System32\Npcap: delay-load it so platform_init() can add
  # that directory to the DLL search path first, and so a missing Npcap gives a
  # readable error instead of a loader failure. Npcap must not be redistributed
  # inside the app; users install it from npcap.com.
  if(MSVC)
    target_link_options(anta-engine PRIVATE /DELAYLOAD:wpcap.dll /DYNAMICBASE /NXCOMPAT /guard:cf)
    target_compile_options(anta-engine PRIVATE /W4 /wd4100 /guard:cf /sdl /EHsc)
  endif()
  target_compile_definitions(anta-engine PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
else()
  find_library(PCAP_LIBRARY NAMES pcap REQUIRED)
  find_path(PCAP_INCLUDE_DIR NAMES pcap/pcap.h)
  if(PCAP_INCLUDE_DIR)
    target_include_directories(anta-engine PRIVATE ${PCAP_INCLUDE_DIR})
  endif()
  target_link_libraries(anta-engine PRIVATE ${PCAP_LIBRARY})
  target_compile_options(anta-engine PRIVATE -Wall -Wextra -Wno-unused-parameter
                         -fstack-protector-strong -D_FORTIFY_SOURCE=2)
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set_target_properties(anta-engine PROPERTIES POSITION_INDEPENDENT_CODE ON)
    target_compile_options(anta-engine PRIVATE -fPIE -fstack-clash-protection)
    target_link_options(anta-engine PRIVATE -pie -Wl,-z,relro,-z,now,-z,noexecstack)
  endif()
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

install(TARGETS anta-engine RUNTIME DESTINATION bin)
