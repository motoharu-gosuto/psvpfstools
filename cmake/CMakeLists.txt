cmake_minimum_required (VERSION 3.0)

project (psvpfstools)

SET(EXECUTABLES psvpfsparser)
SET(LIBRARIES )

include(${CMAKE_SOURCE_DIR}/scripts/ConfigureDependencies.cmake)

configure_boost()

foreach(library ${LIBRARIES})
   include(${CMAKE_SOURCE_DIR}/../${library}/cmake/CMakeLists.txt)
endforeach(library)

foreach(executable ${EXECUTABLES})
   include(${CMAKE_SOURCE_DIR}/../${executable}/cmake/CMakeLists.txt)
endforeach(executable)