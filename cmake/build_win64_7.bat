set BOOST_INCLUDEDIR=N:\boost_1_66_0_install\win_7\include\boost-1_66
set BOOST_LIBRARYDIR=N:\boost_1_66_0_install\win_7\lib_64

set CURL_INCLUDE_DIR=C:\Program Files\curl_win7\include
set CURL_LIBRARY=C:\Program Files\curl_win7\lib\libcurl_imp.lib

set ZLIB_INCLUDE_DIR=N:\zlib
set ZLIB_LIBRARY=N:\zlib\contrib\vstudio\vc11\x64\ZlibStatRelease\zlibstat.lib

rmdir build_win64_7 /S /Q
mkdir build_win64_7
cd build_win64_7
cmake ../ -G "Visual Studio 11 2012 Win64" -DBOOST_MODEL_TAG="-x64"
cd ..
