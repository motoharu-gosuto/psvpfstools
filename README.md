# psvpfstools
PFS R&amp;D

## dependencies

### curl
- Direct installation: https://curl.haxx.se/download.html
- Sources: https://github.com/curl/curl

It is easier to build curl from sources if your are on Windows. By default - it does not have any additional dependencies.
However it looks like Windows binary distribution built with mingw requires openssl binaries:
- libssl-1_1.dll
- libcrypto-1_1.dll

### boost
Any boost version should work out in theory. Build was tested with 1.55 and 1.65.1

## build
On windows you can go to cmake folder and execute build.bat. It will create build folder and configure cmake to build with Visual Studio 2012. Code uses some c++ 11 features so lower Visual Studio is not recommended.
