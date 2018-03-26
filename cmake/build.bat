set BOOST_INCLUDEDIR=N:\svnroot\src\vendor\boost_1_55_0
set BOOST_LIBRARYDIR=N:\svnroot\vendor\boost_1_55_0\vc110\lib

set CURL_INCLUDE_DIR=C:\Program Files (x86)\curl_win7\include
set CURL_LIBRARY=C:\Program Files (x86)\curl_win7\lib\libcurl-d_imp.lib

set ZLIB_INCLUDE_DIR=N:\zlib
set ZLIB_LIBRARY=N:\zlib\contrib\vstudio\vc11\x86\ZlibStatDebug\zlibstat.lib

set LIBTOMCRYPT_INCLUDE_DIR=N:\libtomcrypt\build\include
set LIBTOMCRYPT_LIBRARY=N:\libtomcrypt\build\lib\tomcrypt.lib

rmdir build /S /Q
mkdir build
cd build
cmake ../ -G "Visual Studio 11 2012" 
cd ..