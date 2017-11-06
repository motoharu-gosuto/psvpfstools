cmake_minimum_required (VERSION 3.6.0)

set (PROJECT libzRIF)
project (${PROJECT})

add_library(${PROJECT} STATIC ../keyflate.h
                              ../licdec.h
                              ../rif.h
                              ../keyflate.c
                              ../licdec.cpp)
set_property(TARGET ${PROJECT} PROPERTY FOLDER "libraries")

include_directories(..)
include_directories(../..)