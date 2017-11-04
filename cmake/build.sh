rm build -r -f
mkdir build
cd build
cmake ../ -DCMAKE_BUILD_TYPE=Release
make
cd ..
