#!/bin/bash

set -e

echo
echo "WARNING !!!"
echo
echo "Use only for development and testing!"
echo "It is highly highly not recommended, to use in production!"
echo "This script was based on: https://github.com/curl/curl/blob/curl-8_12_1/docs/HTTP3.md"
echo
echo "Extra packages suggested to be installed: autoconf libtool"
echo

sleep 5

set -x

INSTALL_DIR=$PWD/custom_curl/install
mkdir -p $INSTALL_DIR
cd custom_curl

###

git clone --depth 1 -b openssl-3.1.4+quic https://github.com/quictls/openssl
cd openssl
./config enable-tls1_3 --prefix=$INSTALL_DIR
make -j build_libs
make install_dev
cd ..

git clone --depth 1 -b v1.1.0 https://github.com/ngtcp2/nghttp3
cd nghttp3
git submodule update --init
autoreconf -fi
./configure --prefix=$INSTALL_DIR --enable-lib-only
make -j
make install
cd ..

git clone --depth 1 -b v1.2.0 https://github.com/ngtcp2/ngtcp2
cd ngtcp2
autoreconf -fi
./configure PKG_CONFIG_PATH=$INSTALL_DIR/lib64/pkgconfig:$INSTALL_DIR/lib64/pkgconfig LDFLAGS="-Wl,-rpath,$INSTALL_DIR/lib64" --prefix=$INSTALL_DIR --enable-lib-only --with-openssl
make -j
make install
cd ..

git clone --depth 1 -b v1.64.0 https://github.com/nghttp2/nghttp2
cd nghttp2
autoreconf -fi
./configure PKG_CONFIG_PATH=$INSTALL_DIR/lib64/pkgconfig:$INSTALL_DIR/lib64/pkgconfig LDFLAGS="-Wl,-rpath,$INSTALL_DIR/lib64" --prefix=$INSTALL_DIR --enable-lib-only --with-openssl
make -j
make install
cd ..

git clone --depth 1 -b curl-8_12_1 https://github.com/curl/curl
cd curl
autoreconf -fi
LDFLAGS="-Wl,-rpath,$INSTALL_DIR/lib64" ./configure --with-openssl=$INSTALL_DIR --with-nghttp2=$INSTALL_DIR --with-nghttp3=$INSTALL_DIR --with-ngtcp2=$INSTALL_DIR --prefix=$INSTALL_DIR
make -j
make install
cd ..

###

cd ..
cmake -D CUSTOM_LIBCURL_INSTALL_PATH=$INSTALL_DIR -D CMAKE_BUILD_TYPE=Debug .
make -j
