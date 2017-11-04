set (PROJECT psvpfsparser)
project (${PROJECT})

message(${PROJECT})

FILE (GLOB HEADER_FILES "../aes.h"
                        "../F00DKeyEncryptor.h"
                        "../FilesDbParser.h"
                        "../MerkleTree.h"
                        "../NodeIcvCalculator.h"
                        "../PfsCryptEngine.h"
                        "../PfsCryptEngineBase.h"
                        "../PfsCryptEngineSelectors.h"
                        "../PfsDecryptor.h"
                        "../PfsKeyGenerator.h"
                        "../PfsKeys.h"
                        "../SceKernelUtilsForDriver.h"
                        "../SceSblSsMgrForDriver.h"
                        "../SecretGenerator.h"
                        "../sha1.h"
                        "../UnicvDbParser.h"
                        "../Utils.h")
source_group ("Header Files" FILES ${HEADER_FILES})

FILE (GLOB SOURCE_FILES "../aes.cpp"
                        "../F00DKeyEncryptor.cpp"
                        "../FilesDbParser.cpp"
                        "../MerkleTree.cpp"
                        "../NodeIcvCalculator.cpp"
                        "../PfsCryptEngine.cpp"
                        "../PfsCryptEngineBase.cpp"
                        "../PfsCryptEngineSelectors.cpp"
                        "../PfsDecryptor.cpp"
                        "../PfsKeyGenerator.cpp"
                        "../PfsKeys.cpp"
                        "../psvpfsparser.cpp"
                        "../SceKernelUtilsForDriver.cpp"
                        "../SceSblSsMgrForDriver.cpp"
                        "../SecretGenerator.cpp"
                        "../sha1.cpp"
                        "../UnicvDbParser.cpp"
                        "../Utils.cpp")
source_group ("Source Files" FILES ${SOURCE_FILES})

add_executable (${PROJECT} ${HEADER_FILES} ${SOURCE_FILES})
set_property(TARGET ${PROJECT} PROPERTY FOLDER "executables")
SET(EXECUTABLE_OUTPUT_PATH "${CMAKE_SOURCE_DIR}/output{CMAKE_BUILD_TYPE}")
install(TARGETS ${PROJECT} RUNTIME DESTINATION "bin/{CMAKE_BUILD_TYPE}")

target_link_libraries (${PROJECT} ${Boost_LIBRARIES} ${CURL_LIBRARIES})

include_directories(..)
include_directories(${Boost_INCLUDE_DIRS})
include_directories(${CURL_INCLUDE_DIRS})
