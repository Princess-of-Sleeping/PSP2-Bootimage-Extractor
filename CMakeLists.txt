cmake_minimum_required(VERSION 2.8)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

project(boot_image_extractor)
include("${VITASDK}/share/vita.cmake" REQUIRED)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-q -Wall -O3 -nostdlib")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti -fno-exceptions")

add_executable(boot_image_extractor
  src/main.c
)

target_link_libraries(boot_image_extractor

  k
  gcc
  SceThreadmgrForDriver_stub
  SceIofilemgrForDriver_stub
  SceSysmemForDriver_stub
  taihenForKernel_stub
  taihenModuleUtils_stub

)

vita_create_self(boot_image_extractor.skprx boot_image_extractor
  CONFIG ${CMAKE_SOURCE_DIR}/exports.yml
  UNSAFE
)

