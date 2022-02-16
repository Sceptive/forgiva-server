cmake_minimum_required (VERSION 3.5)
project (forgiva.server)

if (NOT OPENSSL_FOUND)
    find_package(OpenSSL REQUIRED)
endif()


if( OPENSSL_FOUND )
    include_directories(${OPENSSL_INCLUDE_DIR})
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION} ${OPENSSL_ROOT_DIR} ${OPENSSL_INCLUDE_DIR}")
else()
    # Error; with REQUIRED, pkg_search_module() will throw an error by it's own
endif()



if(NOT CMAKE_VERSION VERSION_LESS 3.1)
    set(CMAKE_CXX_STANDARD 11)
    set(CMAKE_C_STANDARD 11)
else()
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -std=c++11")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -std=c++11")

	SET(CMAKE_C_FLAGS "-std=c11 ${CMAKE_C_FLAGS}")

    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -std=c11")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -std=c11")
endif()

set(COMMON_PARAMS, " -Wall -pedantic -Wno-variadic-macros -Wno-unused-command-line-argument")

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} ${COMMON_PARAMS} -g -O0 -DFORGIVA_DEBUG=1 ")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} ${COMMON_PARAMS} -O2 ")

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} ${COMMON_PARAMS}  -g -O0 -DFORGIVA_DEBUG=1 ")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} ${COMMON_PARAMS}  -O2 ")


file(GLOB_RECURSE HEADER_FILES src/*.h)
file(GLOB_RECURSE SOURCE_FILES src/*.c )

if (FORGIVA_DEBUG)
  add_definitions(-DFORGIVA_DEBUG)
endif()


source_group("Header files" FILES ${HEADER_FILES})
source_group("Source files" FILES ${SOURCE_FILES})


list(REMOVE_ITEM SOURCE_FILES "${CMAKE_CURRENT_LIST_DIR}/src/core_main.c")

IF (NOT WIN32)
  # set stuff for windows
  list(REMOVE_ITEM SOURCE_FILES "${CMAKE_CURRENT_LIST_DIR}/src/3rdparty/scrypt/win32/mman.c")
  list(REMOVE_ITEM SOURCE_FILES "${CMAKE_CURRENT_LIST_DIR}/src/3rdparty/scrypt/win32/mman.h")
ENDIF()


#MESSAGE("Source files: " ${SOURCE_FILES})


add_library(forgiva_server_common STATIC ${SOURCE_FILES} ${HEADER_FILES})

add_executable(forgiva_server "${CMAKE_CURRENT_LIST_DIR}/src/core_main.c"  )

IF (NOT WIN32)
target_link_libraries(forgiva_server forgiva_server_common ${OPENSSL_LIBRARIES} m dl pthread)
ELSE()
target_link_libraries(forgiva_server forgiva_server_common ${OPENSSL_LIBRARIES} wsock32 m pthread)
ENDIF()
