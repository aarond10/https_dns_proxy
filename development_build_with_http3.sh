#!/bin/bash

set -e

echo
echo "WARNING !!!"
echo
echo "Use only for development and testing!"
echo "It is highly highly not recommended, to use in production!"
echo "This script was based on: https://github.com/curl/curl/blob/curl-8_19_0/docs/HTTP3.md"
echo
echo "Extra packages suggested to be installed: pkg-config pkgconf autoconf automake libtool"
echo

sleep 5

set -x

INSTALL_DIR=$PWD/custom_curl/install
mkdir -p $INSTALL_DIR
cd custom_curl

###

git clone --depth 1 -b openssl-3.5.6 https://github.com/openssl/openssl
cd openssl
./config --prefix=$INSTALL_DIR --libdir=lib
make -j
make install_dev
cd ..

git clone --depth 1 -b v1.15.0 https://github.com/ngtcp2/nghttp3
cd nghttp3
git submodule update --init
autoreconf -fi
./configure --prefix=$INSTALL_DIR --enable-lib-only
make -j
make install
cd ..

git clone --depth 1 -b v1.22.0 https://github.com/ngtcp2/ngtcp2
cd ngtcp2
autoreconf -fi
./configure PKG_CONFIG_PATH=$INSTALL_DIR/lib/pkgconfig LDFLAGS="-Wl,-rpath,$INSTALL_DIR/lib" --prefix=$INSTALL_DIR --enable-lib-only --with-openssl
make -j
make install
cd ..

git clone --depth 1 -b v1.68.1 https://github.com/nghttp2/nghttp2
cd nghttp2
autoreconf -fi
./configure PKG_CONFIG_PATH=$INSTALL_DIR/lib/pkgconfig LDFLAGS="-Wl,-rpath,$INSTALL_DIR/lib" --prefix=$INSTALL_DIR --enable-lib-only --with-openssl
make -j
make install
cd ..

git clone --depth 1 -b curl-8_19_0 https://github.com/curl/curl
cd curl
autoreconf -fi
LDFLAGS="-Wl,-rpath,$INSTALL_DIR/lib" ./configure PKG_CONFIG_PATH=$INSTALL_DIR/lib/pkgconfig --with-openssl=$INSTALL_DIR --with-nghttp2=$INSTALL_DIR --with-nghttp3=$INSTALL_DIR --with-ngtcp2=$INSTALL_DIR --prefix=$INSTALL_DIR --without-libpsl
make -j
make install
cd ..

###

cd ..
cmake -D CUSTOM_LIBCURL_INSTALL_PATH=$INSTALL_DIR -D CMAKE_BUILD_TYPE=Debug .
make -j
