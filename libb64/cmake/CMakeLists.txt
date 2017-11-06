cmake_minimum_required(VERSION 2.8.1)

set (PROJECT libb64)
project (${PROJECT})

add_library(${PROJECT} STATIC ../cencode.c 
                              ../cdecode.c 
                              ../b64/cdecode.h 
                              ../b64/cencode.h 
                              ../b64/cdecode.h)
set_property(TARGET ${PROJECT} PROPERTY FOLDER "libraries")

include_directories(..)
