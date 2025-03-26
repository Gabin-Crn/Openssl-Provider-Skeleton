cmake_minimum_required(VERSION 3.29)
project(Openssl_Provider_Skeleton C)

set(CMAKE_C_STANDARD 11)

# Path to Openssl
set(OPENSSL_ROOT_DIR "C:/LegacyApp/OpenSSL-Win64")
set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")
set(OPENSSL_LIB_DIR "${OPENSSL_ROOT_DIR}/lib/VC/x64/MD")

# Header
include_directories(${OPENSSL_INCLUDE_DIR})
link_directories(${OPENSSL_LIB_DIR})

# DLL Creation
add_library(myProvider SHARED
        myProvider.c
        myProvider.h
)

# Windows Properties
set_target_properties(myProvider PROPERTIES
        CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS TRUE
        POSITION_INDEPENDENT_CODE ON
)

# Link with libcrypto
target_link_libraries(myProvider
        ${OPENSSL_LIB_DIR}/libcrypto.lib
)


