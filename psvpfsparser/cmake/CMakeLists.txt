set (PROJECT psvpfsparser)
project (${PROJECT})

message(${PROJECT})

FILE (GLOB HEADER_FILES "../F00DKeyEncryptor.h"
                        "../FilesDbParser.h"
                        "../HashTree.h"
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
                        "../UnicvDbParser.h"
                        "../UnicvDbTypes.h"
                        "../UnicvDbUtils.h"
                        "../Utils.h"
                        "../PsvPfsParserConfig.h"
                        "../LocalKeyGenerator.h"
                        "../LocalKeys.h"
                        "../MerkleTree.hpp"
                        "../IcvPrimitives.h")
source_group ("Header Files" FILES ${HEADER_FILES})

FILE (GLOB SOURCE_FILES "../F00DKeyEncryptor.cpp"
                        "../FilesDbParser.cpp"
                        "../HashTree.cpp"
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
                        "../UnicvDbParser.cpp"
                        "../UnicvDbTypes.cpp"
                        "../UnicvDbUtils.cpp"
                        "../Utils.cpp"
                        "../PsvPfsParserConfig.cpp"
                        "../LocalKeyGenerator.cpp"
                        "../LocalKeys.cpp"
                        "../IcvPrimitives.cpp")
source_group ("Source Files" FILES ${SOURCE_FILES})

add_executable (${PROJECT} ${HEADER_FILES} ${SOURCE_FILES})
set_property(TARGET ${PROJECT} PROPERTY FOLDER "executables")
set(EXECUTABLE_OUTPUT_PATH "${CMAKE_SOURCE_DIR}/output/${CMAKE_BUILD_TYPE}")
install(TARGETS ${PROJECT} RUNTIME DESTINATION bin)

target_link_libraries (${PROJECT} ${Boost_LIBRARIES} ${CURL_LIBRARIES} libzRIF libb64 libcrypto ${ZLIB_LIBRARIES})

include_directories(..)
include_directories(../..)
include_directories(${Boost_INCLUDE_DIRS})
include_directories(${CURL_INCLUDE_DIRS})
include_directories(${ZLIB_INCLUDE_DIRS})

