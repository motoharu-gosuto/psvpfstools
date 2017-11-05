#environment variables for configure_boost have to be set
#BOOST_INCLUDEDIR
#BOOST_LIBRARYDIR
#BOOST_ROOT

macro(configure_boost)

message("configuring boost")

set (Boost_USE_STATIC_LIBS ON)
set (Boost_USE_MULTITHREADED ON)

set (BOOST_COMPONENTS system 
                      filesystem
                      program_options)

FIND_PACKAGE(Boost COMPONENTS ${BOOST_COMPONENTS} REQUIRED)

if(Boost_FOUND)
message("Using Boost_VERSION: ${Boost_VERSION}")
message("Using Boost_INCLUDE_DIRS: ${Boost_INCLUDE_DIRS}")
message("Using Boost_LIBRARY_DIRS: ${Boost_LIBRARY_DIRS}")
else()
message("Boost library is not found")
endif()

endmacro(configure_boost)

#environment variables for configure_curl have to be set
#CURL_INCLUDE_DIR
#CURL_LIBRARY

macro(configure_curl)

message("configuring curl")

set(CURL_INCLUDE_DIR "$ENV{CURL_INCLUDE_DIR}")
set(CURL_LIBRARY "$ENV{CURL_LIBRARY}")

FIND_PACKAGE(CURL REQUIRED)

if(CURL_FOUND)
message("Using CURL_VERSION_STRING: ${CURL_VERSION_STRING}")
message("Using CURL_INCLUDE_DIRS: ${CURL_INCLUDE_DIRS}")
message("Using CURL_LIBRARIES: ${CURL_LIBRARIES}")
else()
message("Curl library is not found")
endif()

endmacro(configure_curl)