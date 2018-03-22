cmake_minimum_required (VERSION 3.6.0)

set (PROJECT psvpfstools)
project (${PROJECT})

if (MSVC)
   add_definitions (/W3)
   add_definitions(-D_SCL_SECURE_NO_WARNINGS)
elseif (CMAKE_COMPILER_IS_GNUCXX)
   set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Wno-unknown-pragmas -fPIC")
else()
   message (FATAL_ERROR "Unknown compiler")
   return()
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Build type is not specified. Set to Release.")
  set(CMAKE_BUILD_TYPE Release)
endif()

#additional search paths for cmake (in case of some custom dependencies)
set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/scripts/")

include(scripts/ConfigureDependencies.cmake)

configure_boost()
configure_curl()
configure_zlib()

SET(EXECUTABLES psvpfsparser)
SET(LIBRARIES libb64
              libzRIF)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

foreach(library ${LIBRARIES})
   add_subdirectory(../${library}/cmake libraries/${library})
endforeach(library)

foreach(executable ${EXECUTABLES})
   add_subdirectory(../${executable}/cmake executables/${executable})
endforeach(executable)
