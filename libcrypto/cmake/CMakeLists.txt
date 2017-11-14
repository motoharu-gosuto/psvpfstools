cmake_minimum_required (VERSION 3.6.0)

set (PROJECT libcrypto)
project (${PROJECT})

add_library(${PROJECT} STATIC ../sha1.h
                              ../sha1.cpp
                              ../aes.h
                              ../aes.cpp
                              ../sha256.h
                              ../sha256.cpp
                              ../sha256-internal.cpp
                              ../sha256_i.h
                              ../crypto.h)
set_property(TARGET ${PROJECT} PROPERTY FOLDER "libraries")

include_directories(..)
include_directories(../..)