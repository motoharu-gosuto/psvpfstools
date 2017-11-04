cmake_minimum_required (VERSION 3.0)

set (PROJECT psvpfsparser)
project (${PROJECT})

message(${PROJECT})

set(SOURCE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../${PROJECT_NAME})

FILE (GLOB HEADER_FILES "${SOURCE_PATH}/aes.h"
                        "${SOURCE_PATH}/F00DKeyEncryptor.h"
                        "${SOURCE_PATH}/FilesDbParser.h"
                        "${SOURCE_PATH}/MerkleTree.h"
                        "${SOURCE_PATH}/NodeIcvCalculator.h"
                        "${SOURCE_PATH}/PfsCryptEngine.h"
                        "${SOURCE_PATH}/PfsCryptEngineBase.h"
                        "${SOURCE_PATH}/PfsCryptEngineSelectors.h"
                        "${SOURCE_PATH}/PfsDecryptor.h"
                        "${SOURCE_PATH}/PfsKeyGenerator.h"
                        "${SOURCE_PATH}/PfsKeys.h"
                        "${SOURCE_PATH}/SceKernelUtilsForDriver.h"
                        "${SOURCE_PATH}/SceSblSsMgrForDriver.h"
                        "${SOURCE_PATH}/SecretGenerator.h"
                        "${SOURCE_PATH}/sha1.h"
                        "${SOURCE_PATH}/UnicvDbParser.h"
                        "${SOURCE_PATH}/UnicvDbPrint.h"
                        "${SOURCE_PATH}/Utils.h")
source_group ("Header Files" FILES ${HEADER_FILES})

FILE (GLOB SOURCE_FILES "${SOURCE_PATH}/aes.cpp"
                        "${SOURCE_PATH}/F00DKeyEncryptor.cpp"
                        "${SOURCE_PATH}/FilesDbParser.cpp"
                        "${SOURCE_PATH}/FilesDbPrint.cpp"
                        "${SOURCE_PATH}/MerkleTree.cpp"
                        "${SOURCE_PATH}/NodeIcvCalculator.cpp"
                        "${SOURCE_PATH}/PfsCryptEngine.cpp"
                        "${SOURCE_PATH}/PfsCryptEngineBase.cpp"
                        "${SOURCE_PATH}/PfsCryptEngineSelectors.cpp"
                        "${SOURCE_PATH}/PfsDecryptor.cpp"
                        "${SOURCE_PATH}/PfsKeyGenerator.cpp"
                        "${SOURCE_PATH}/PfsKeys.cpp"
                        "${SOURCE_PATH}/psvpfsparser.cpp"
                        "${SOURCE_PATH}/SceKernelUtilsForDriver.cpp"
                        "${SOURCE_PATH}/SceSblSsMgrForDriver.cpp"
                        "${SOURCE_PATH}/SecretGenerator.cpp"
                        "${SOURCE_PATH}/sha1.cpp"
                        "${SOURCE_PATH}/UnicvDbParser.cpp"
                        "${SOURCE_PATH}/UnicvDbPrint.cpp"
                        "${SOURCE_PATH}/Utils.cpp")
source_group ("Source Files" FILES ${SOURCE_FILES})

add_executable(${PROJECT} ${HEADER_FILES} ${SOURCE_FILES})
SET(EXECUTABLE_OUTPUT_PATH "${CMAKE_SOURCE_DIR}/output")

target_link_libraries (${PROJECT} ${Boost_LIBRARIES})

include_directories(..)
include_directories(${Boost_INCLUDE_DIRS})