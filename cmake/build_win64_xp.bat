set BOOST_INCLUDEDIR=N:\boost_1_66_0_install\win_xp\include\boost-1_66
set BOOST_LIBRARYDIR=N:\boost_1_66_0_install\win_xp\lib_64

set ZLIB_INCLUDE_DIR=N:\zlib
set ZLIB_LIBRARY=N:\zlib\contrib\vstudio\vc11\x64\ZlibStatRelease-WinXP\zlibstat.lib

rmdir build_win64_xp /S /Q
mkdir build_win64_xp
cd build_win64_xp
cmake ../ -G "Visual Studio 11 2012 Win64" -T v110_xp -DBOOST_MODEL_TAG="-x64"
cd ..
