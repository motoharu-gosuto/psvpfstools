# psvpfstools

## Introduction

This is a set of tools that allows to decrypt PFS filesystem layer of PS Vita.

In the past the only good way to do this was to mount PFS for example in Vita Shell and let PS Vita to decrypt the files.

However this tool is a completely new standalone approach that **does not require you to have PS Vita**.

All decryption is done **directly on the PC**.

## Public F00D service

PFS tools were designed in such a way that implementation of F00D crypto layer can be provided separately.

Currently you can use a service url located at: http://cma.henkaku.xyz

## What exactly can be decrypted?

In theory everything that is PFS encrypted can be decrypted.

The tool was tested on some games, including 3.61+ and DLCs.

In case of specific problems please refer to the next section.

## Reporting issues

PFS tools are still under developement and testing. 

If you find bugs or have problems with decrypting specific application please consider leaving a report here:

https://github.com/motoharu-gosuto/psvpfstools/issues

## dependencies

### curl

#### Windows (example)
- Direct installation: https://curl.haxx.se/download.html
- Sources: https://github.com/curl/curl

It is easier to build curl from sources if your are on Windows. By default - it does not have any additional dependencies.
However it looks like Windows binary distribution built with mingw requires openssl binaries:
- libssl-1_1.dll
- libcrypto-1_1.dll

You have to set these environment variables for cmake:
- CURL_INCLUDE_DIR=C:\Program Files (x86)\CURL\include
- CURL_LIBRARY=C:\Program Files (x86)\CURL\lib\libcurl_imp.lib
#### Ubuntu (example)
You can install curl library with apt-get: apt-get install libcurl4-gnutls-dev or libcurl4-openssl-dev

### boost

#### Windows (example)
Any boost version should work out in theory. Build was tested with 1.55 and 1.65.1
Consult with this page for build:
http://www.boost.org/doc/libs/1_65_1/more/getting_started/windows.html

You have to set these environment variables for cmake:
- BOOST_INCLUDEDIR=C:\boost_1_55_0
- BOOST_LIBRARYDIR=C:\boost_1_55_0\vc110\lib
#### Ubuntu (example)
You can install boost with apt-get: libboost-all-dev

### zlib

#### Windows (example)
- Sources: https://github.com/madler/zlib

You have to set these environment variables for cmake:
- ZLIB_INCLUDE_DIR=ZLIB_INCLUDE_DIR=C:\zlib
- ZLIB_LIBRARY=C:\zlib\contrib\vstudio\vc11\x86\ZlibStatDebug\zlibstat.lib

#### Ubuntu (example)
You can install zlib with apt-get: zlib1g-dev

## build

### Windows
Go to cmake folder and execute build.bat. It will create build folder and configure cmake to build with Visual Studio 2012. Code uses some c++ 11 features so lower Visual Studio is not recommended.

### Ubuntu
Go to cmake folder and execute build.sh. It will create build folder and configure cmake to build with standard make.

## run
Options:

  -h [ --help ]             Show help
  
  -i [ --title_id_src ] arg Source directory that contains the application.
                            Like PCSC00000.
                            
  -o [ --title_id_dst ] arg Destination directory where everything will be
                            unpacked. Like PCSC00000_dec.
                            
  -k [ --klicensee ] arg    klicensee hex coded string. Like
                            00112233445566778899AABBCCDDEEFF.
                            
  -z [ --zRIF ] arg         zRIF string.
  
  -f [ --f00d_url ] arg     Url of F00D service.
  
## Special thanks  
- Proxima. For initial docs on DMAC5, providing F00D service and help with crypto theory. 
- St4rk, weaknespase and everyone involved in PkgDecrypt. For zRIF string decode/inflate code.
- Chris Venter. For libb64.
- PolarSSL. For cryptographic primitives.
