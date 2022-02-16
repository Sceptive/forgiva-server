#!/usr/bin/bash
set -e

FS_HOME=$(dirname $(realpath ${BASH_SOURCE[0]}))

cd ${FS_HOME}/

if [[ "$1" == "release" ]] || [[ "$1" == "image" ]] || [[ "$1" == "test" ]]; then 
    LNX_X64_DIR_REL=build/linux-x86_64-release
    LNX_X64_DIR_DBG=build/linux-x86_64-debug
    WIN_X64_DIR_REL=build/mingw64-release
    WIN_X64_DIR_DBG=build/mingw64-debug

    TAGV=`git describe --tags --long`
    REV=`git log --oneline | wc -l | tr -d ' '`
    VER=${TAGV%%-*}-$REV


    (docker build -t forgiva_server_build -f Dockerfile.BuildEnv . && \
    mkdir -p build && \
    export id=$(docker create forgiva_server_build) && \
    docker cp $id:/work/$LNX_X64_DIR_REL/forgiva_server     build/forgiva_server-$VER-linux-x86_64-release && \
    docker cp $id:/work/$LNX_X64_DIR_DBG/forgiva_server     build/forgiva_server-$VER-linux-x86_64-debug && \
    docker cp $id:/work/$WIN_X64_DIR_REL/forgiva_server.exe build/forgiva_server-$VER-mingw64-release.exe && \
    docker cp $id:/work/$WIN_X64_DIR_DBG/forgiva_server.exe build/forgiva_server-$VER-mingw64-debug.exe && \
    docker rm -v $id && \
    tar -C build -cJvf forgiva_server-$VER-cp-release.tar.xz forgiva_server-$VER-linux-x86_64-release forgiva_server-$VER-mingw64-release.exe 
    )
    if [[ "$1" == "image" ]]; then

        docker build -t forgiva_server:${VER} --build-arg VER=${VER} -f Dockerfile .

    fi
    if [[ "$1" == "test" ]]; then

        build/forgiva_server-$VER-linux-x86_64-release -t

    fi
else
    if [ ! -f "build/local/openssl-linux-x86_64/bin/openssl" ]; then
        echo "Building OpenSSL"
        (mkdir -p build/local/openssl-linux_x86_64 && \
        cd build/local && \
        rm -rf openssl-1.0.2n && \
        tar zxvf ../../etc/openssl-1.0.2n.tar.gz 2>&1 > /dev/null && \
        cd openssl-1.0.2n && \
        ./Configure linux-x86_64 --openssldir=`pwd`/../openssl-linux-x86_64 2>&1 > /dev/null  && \
        (make -j 8)  2>&1 > /dev/null && \
        make install  2>&1 > /dev/null && \
        cd .. && \
        rm -rf openssl-1.0.2n
        ) || { echo "Could not build OpenSSL " ; exit 1 ; }
    fi
    if [ ! -f "build/local/Makefile" ]; then
        (mkdir -p build/local && \
        cd build/local && \
        export OPENSSL_BUILD_DIR=`pwd`/openssl-linux-x86_64 &&
        echo "set(OPENSSL_FOUND TRUE)"  > toolchain.cmake && \
        echo "set(OPENSSL_ROOT_DIR ${OPENSSL_BUILD_DIR})"  >> toolchain.cmake && \
        echo "set(OPENSSL_INCLUDE_DIR ${OPENSSL_BUILD_DIR}/include)"  >> toolchain.cmake && \
        echo "set(OPENSSL_CRYPTO_LIBRARIES ${OPENSSL_BUILD_DIR}/lib/libcrypto.a)"  >> toolchain.cmake && \
        echo "set(OPENSSL_SSL_LIBRARIES ${OPENSSL_BUILD_DIR}/lib/libssl.a)"  >> toolchain.cmake && \
        echo "set(OPENSSL_LIBRARIES \${OPENSSL_SSL_LIBRARIES} \${OPENSSL_CRYPTO_LIBRARIES})"  >> toolchain.cmake && \
        cmake -DCMAKE_TOOLCHAIN_FILE="toolchain.cmake" -DCMAKE_BUILD_TYPE=Debug -DFORGIVA_DEBUG=ON ../.. && 
        make -j 4
        ) || { echo "Could not initially build Forgiva " ; exit 1 ; }
    else
        (cd build/local && make -j 4 ) || { echo "Build Failed" ; exit 1 ; }
        cat etc/test.json| build/local/forgiva_server -s
    fi
fi
