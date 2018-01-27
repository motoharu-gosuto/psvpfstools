set BOOST_INCLUDEDIR=N:\boost_1_66_0_install\win_7\include\boost-1_66
set BOOST_LIBRARYDIR=N:\boost_1_66_0_install\win_7\lib_32

set CURL_INCLUDE_DIR=C:\Program Files (x86)\curl_win7\include
set CURL_LIBRARY=C:\Program Files (x86)\curl_win7\lib\libcurl_imp.lib

set ZLIB_INCLUDE_DIR=N:\zlib
set ZLIB_LIBRARY=N:\zlib\contrib\vstudio\vc11\x86\ZlibStatRelease\zlibstat.lib

rmdir build_win32_7 /S /Q
mkdir build_win32_7
cd build_win32_7
cmake ../ -G "Visual Studio 11 2012" -DBOOST_MODEL_TAG="-x32"
cd ..
