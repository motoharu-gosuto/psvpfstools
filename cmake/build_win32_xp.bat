set BOOST_INCLUDEDIR=N:\boost_1_66_0_install\win_xp\include\boost-1_66
set BOOST_LIBRARYDIR=N:\boost_1_66_0_install\win_xp\lib_32

set ZLIB_INCLUDE_DIR=N:\zlib
set ZLIB_LIBRARY=N:\zlib\contrib\vstudio\vc11\x86\ZlibStatRelease-WinXP\zlibstat.lib

rmdir build_win32_xp /S /Q
mkdir build_win32_xp
cd build_win32_xp
cmake ../ -G "Visual Studio 11 2012" -T v110_xp -DBOOST_MODEL_TAG="-x32"
cd ..
