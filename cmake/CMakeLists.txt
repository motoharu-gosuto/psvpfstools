cmake_minimum_required (VERSION 3.6.0)

set (PROJECT psvpfstools)
project (${PROJECT})

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Build type is not specified. Set to release.")
  set(CMAKE_BUILD_TYPE Release)
endif()

#set additional search paths for cmake scripts (in case of some custom dependencies)
set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/scripts/")

include(scripts/ConfigureDependencies.cmake)

configure_boost()
configure_curl()

SET(EXECUTABLES psvpfsparser)
SET(LIBRARIES )

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

foreach(library ${LIBRARIES})
   add_subdirectory(../${library}/cmake libraries/${library})
endforeach(library)

foreach(executable ${EXECUTABLES})
   add_subdirectory(../${executable}/cmake executables/${executable})
endforeach(executable)