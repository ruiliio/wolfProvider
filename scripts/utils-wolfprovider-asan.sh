#!/bin/bash
#
# Copyright (C) 2006-2025 wolfSSL Inc.
#
# This file is part of wolfProvider.
#
# wolfProvider is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfProvider is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with wolfProvider. If not, see <http://www.gnu.org/licenses/>.
#

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
source ${SCRIPT_DIR}/utils-openssl.sh
source ${SCRIPT_DIR}/utils-wolfssl.sh

WOLFPROV_SOURCE_DIR=${SCRIPT_DIR}/..
WOLFPROV_INSTALL_DIR=${SCRIPT_DIR}/../wolfprov-asan-install
if [ "$WOLFSSL_ISFIPS" -eq "1" ] || [ -n "$WOLFSSL_FIPS_BUNDLE" ]; then
    WOLFPROV_CONFIG=${WOLFPROV_CONFIG:-"$WOLFPROV_SOURCE_DIR/provider-fips.conf"}
else
    WOLFPROV_CONFIG=${WOLFPROV_CONFIG:-"$WOLFPROV_SOURCE_DIR/provider.conf"}
fi

WOLFPROV_NAME="libwolfprov"
WOLFPROV_PATH=$WOLFPROV_INSTALL_DIR/lib

# Always enable debug for ASAN builds
WOLFPROV_DEBUG=1

# ASAN flags
ASAN_CFLAGS="-fsanitize=address -g -O1 -fno-omit-frame-pointer"
ASAN_LDFLAGS="-fsanitize=address"

install_wolfprov_asan() {
    cd ${WOLFPROV_SOURCE_DIR}

    # Set ASAN environment variables for OpenSSL and wolfSSL builds
    export CFLAGS="${ASAN_CFLAGS}"
    export LDFLAGS="${ASAN_LDFLAGS}"
    
    init_openssl
    init_wolfssl
    unset OPENSSL_MODULES
    unset OPENSSL_CONF
    printf "LD_LIBRARY_PATH: $LD_LIBRARY_PATH\n"

    printf "\tConfigure wolfProvider with ASAN ... "
    if [ ! -e "${WOLFPROV_SOURCE_DIR}/configure" ]; then
        ./autogen.sh >>$LOG_FILE 2>&1
    fi
    
    # Configure with ASAN flags
    ./configure --with-openssl=${OPENSSL_INSTALL_DIR} \
                --with-wolfssl=${WOLFSSL_INSTALL_DIR} \
                --prefix=${WOLFPROV_INSTALL_DIR} \
                --enable-debug \
                CFLAGS="${ASAN_CFLAGS}" \
                LDFLAGS="${ASAN_LDFLAGS}" >>$LOG_FILE 2>&1
    RET=$?
    
    if [ $RET != 0 ]; then
        printf "\n\n...\n"
        tail -n 40 $LOG_FILE
        do_cleanup
        exit 1
    fi
    printf "Done.\n"

    printf "\tBuild wolfProvider with ASAN ... "
    make -j$NUMCPU >>$LOG_FILE 2>&1
    if [ $? != 0 ]; then
        printf "\n\n...\n"
        tail -n 40 $LOG_FILE
        do_cleanup
        exit 1
    fi
    printf "Done.\n"

    printf "\tInstall wolfProvider with ASAN ... "
    make install >>$LOG_FILE 2>&1
    if [ $? != 0 ]; then
        printf "\n\n...\n"
        tail -n 40 $LOG_FILE
        do_cleanup
        exit 1
    fi
    printf "Done.\n"
}

init_wolfprov_asan() {
    install_wolfprov_asan
    printf "\twolfProvider with ASAN installed in: ${WOLFPROV_INSTALL_DIR}\n"

    export OPENSSL_MODULES=$WOLFPROV_PATH
    export OPENSSL_CONF=${WOLFPROV_CONFIG}
    
    # Set comprehensive ASAN options for thorough error detection
    export ASAN_OPTIONS="detect_leaks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1:detect_invalid_pointer_pairs=2:detect_container_overflow=1:strict_string_checks=1:halt_on_error=0:print_stacktrace=1:fast_unwind_on_malloc=0:malloc_context_size=30:symbolize=1"
}
