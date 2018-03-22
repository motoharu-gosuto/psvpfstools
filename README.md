# psvpfstools

## Introduction

This is a set of tools that allows to decrypt PFS filesystem layer of PS Vita.

In the past the only good way to do this was to mount PFS for example in Vita Shell and let PS Vita to decrypt the files.

However this tool is a completely new standalone approach that **does not require you to have PS Vita**.

All decryption is done **directly on the PC**.

## Public F00D service

PFS tools were designed in such a way that implementation of F00D crypto layer can be provided separately.

Currently you can use a service url located at: http://cma.henkaku.xyz

## Why do I need F00D service?

The only purpose of F00D service is to take the given key, encrypt it and give it back. F00D service **does not decrypt PFS**. To those that are curious - service **does not use PS Vita** as well.

Typically during decryption process service is called only once to encrypt klicensee that is extracted from zRIF string if you are decrypting gamedata or addcont (unicv.db format). Service is called once to encrypt key that is extracted from sealedkey file if you are decrypting savedata, trophies, appmeta, addcont root (icv.db format).

On Vita - there are 3 hardware implementations of crypto functions:
- Use key - you have a freedom of giving the key to crypto function and key is used directly.
- Use slot_id - you have to set the key into specific slot. Then by specifying key_id you instruct F00D to encrypt your key with specific key from F00D. Encrypted key is then used in crypto function of your choice.
- Use key_id - you give the key and specify key_id. Your key is then encrypted with specific key from F00D. Encrypted key is then put into one of the slots in default range. After that encrypted key can be used in crypto function of your choice.

You can read more about crypto functions here:
https://wiki.henkaku.xyz/vita/SceSblSsMgr#SceSblSsMgrForDriver

## F00D service cache ##

Instead of using F00D service directly it is now possible to use a cache file that is created beforehand.

To use it pass path to the file with --f00d_cache option.

When using --f00d_url option you will get an `F00D cache` output that you can copy to a cache file.

Two types of files are allowed: 

* flat files with delimiters like " ", "\t", ","
* json files

### Format of flat files ###

* titleid (only for information, not used)
* klicensee
* encrypted key

```
PCSE00000 00000000000000000000000000000000 00000000000000000000000000000000
PCSE11111 11111111111111111111111111111111 11111111111111111111111111111111
PCSE22222 22222222222222222222222222222222 22222222222222222222222222222222
```

### Format of json files ###

```
{
   "PCSE00000" : 
   {
      "key" : "00000000000000000000000000000000",
      "value" : "00000000000000000000000000000000"
   },
   "PCSE11111" :
   {
      "key" : "11111111111111111111111111111111",
      "value" : "11111111111111111111111111111111"
   },
   "PCSE22222" :
   {
      "key" : "22222222222222222222222222222222",
      "value" : "22222222222222222222222222222222"
   }
}

```

## What exactly can be decrypted?

Tool now supports both icv.db and unicv.db formats.

Which means that it can decrypt gamedata, addcont, savedata, trophies, appmeta, addcont root.

In theory everything that is PFS encrypted can be decrypted.

The tool was tested in all scenarios listed above, including 3.61+ games.

In case of specific problems please refer to the next section.

## Reporting issues

PFS tools are still under developement and testing. 

If you find bugs or have problems with decrypting specific data please consider leaving a report here:

https://github.com/motoharu-gosuto/psvpfstools/issues

## dependencies

### libtomcrypt

#### Windows (example)
First you have to build libtommath: https://github.com/libtom/libtommath

- Start Visual Studio command prompt
- Navigate to libtommath directory
- Locate `makefile.msvc` file and edit it - remove `/Fo$@` according to: https://groups.google.com/forum/#!msg/comp.os.ms-windows.programmer.win32/JYoUvSNU0Uc/_JOKS7vek0sJ
- Execute the following commands:

```
nmake -f makefile.msvc
```

This will build target which contains tommath.lib.

Having built libtommath you can now build libtomcrypt.

- Start Visual Studio command prompt
- Navigate to libtomcrypt directory
- Execute the following commands:

```
nmake -f makefile.msvc CFLAGS="/DUSE_LTM /DLTM_DESC /IC:\libtommath" EXTRALIBS=C:\libtommath\tommath.lib default
mkdir build
nmake -f makefile.msvc PREFIX=C:\libtomcrypt\build install
```

This will build default target which contains tomcrypt.lib and install everything to corresponding build directory.

You have to set these environment variables for cmake:
- TOMCRYPT_INCLUDE_DIR=N:\libtomcrypt\build\include
- TOMCRYPT_LIBRARY=N:\libtomcrypt\build\lib\tomcrypt.lib

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
You can install curl library with apt-get: 

```
apt-get install libcurl4-gnutls-dev
```
or
```
apt-get install libcurl4-openssl-dev
```

### boost

#### Windows (example)
Any boost version should work out in theory. Build was tested with 1.55 and 1.65.1

To build boost with Visual Studio 2012 you can follow these steps
- Start Visual Studio command prompt
- Navigate to boost directory
- Execute the following commands

```
bootstrap.bat
b2 toolset=msvc-11.0 address-model=64 --build-type=complete stage
```

First command sets up build system. Second command builds boost libraries. 
You can remove address-model argument if you need 32 bit build.
If you want to use different version of Visual Studio - change toolset parameter.
If you need different type of build - look at such options as variant, link, runtime-link.
Build type complete will build all library variations.

Win7 static linking release x32
```
b2 toolset=msvc-11.0 address-model=32 link=static variant=release stage install --prefix=<path>
```
Win7 static linking release x64
```
b2 toolset=msvc-11.0 address-model=64 link=static variant=release stage install --prefix=<path>
```
WinXP static linking release x32
```
b2 toolset=msvc-11.0_xp address-model=32 link=static variant=release stage install --prefix=<path>
```
WinXP static linking release x64
```
b2 toolset=msvc-11.0_xp address-model=64 link=static variant=release stage install --prefix=<path>
```

For additional reference - consult with this page for windows build:
http://www.boost.org/doc/libs/1_65_1/more/getting_started/windows.html

You have to set these environment variables for cmake:
- BOOST_INCLUDEDIR=C:\boost_1_55_0
- BOOST_LIBRARYDIR=C:\boost_1_55_0\vc110\lib
#### Ubuntu (example)
You can install boost with apt-get: 

```
apt-get install libboost-all-dev
```

### zlib

#### Windows (example)
- Sources: https://github.com/madler/zlib

You have to set these environment variables for cmake:
- ZLIB_INCLUDE_DIR=C:\zlib
- ZLIB_LIBRARY=C:\zlib\contrib\vstudio\vc11\x86\ZlibStatDebug\zlibstat.lib

#### Ubuntu (example)
You can install zlib with apt-get: 

```
aptget install zlib1g-dev
```

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
  
  -c [ --f00d_cache] arg    Path to flat or json file with F00D cache.
  
## Special thanks  
- Proxima. For initial docs on DMAC5, contributing code for keystone and sealedkey checks, providing F00D service and help with crypto theory. 
- St4rk, weaknespase and everyone involved in PkgDecrypt. For zRIF string decode/inflate code.
- devnoname120 for hmac_sha256 crypto primitives.
- SilicaAndPina for pointing at trophy and savedata pfs.
- CelesteBlue for indicating possibility of sealedkey usage as local key.
- tomazzz369 for testing and providing XP build
- MRGhidini for testing and integration into Psvimgtools-Easy-FrontEnd

## Other thanks
- Chris Venter. For libb64. Integrated as source.
- PolarSSL. For cryptographic primitives. Integrated as source.
