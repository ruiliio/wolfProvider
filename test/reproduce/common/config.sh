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

# Central configuration file for all test scripts
# This file defines common variables and settings used across all test scripts

# Define the wolfProvider installation directory
# This can be overridden by setting WOLFPROV_INSTALL_DIR in the environment
WOLFPROV_INSTALL_DIR=${WOLFPROV_INSTALL_DIR:-"$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../wolfprov-install" && pwd)"}

# Define the wolfProvider configuration file
# This can be overridden by setting WOLFPROV_CONFIG in the environment
WOLFPROV_CONFIG=${WOLFPROV_CONFIG:-"$(dirname "${BASH_SOURCE[0]}")/../../../provider.conf"}

# Define the OpenSSL modules directory
# This is typically the lib directory in the wolfProvider installation
OPENSSL_MODULES=${OPENSSL_MODULES:-"$WOLFPROV_INSTALL_DIR/lib"}

# Define the wolfProvider directory (root of the repository)
WOLFPROV_DIR=${WOLFPROV_DIR:-"$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../" && pwd)"}

# Define common test parameters
DEFAULT_TEST_ITERATIONS=100
DEFAULT_HASH_ALGORITHMS="SHA1 SHA256 SHA384 SHA512"

# Define common environment setup function
setup_environment() {
    # Export necessary environment variables
    export WOLFPROV_INSTALL_DIR
    export WOLFPROV_CONFIG
    export OPENSSL_MODULES
    export OPENSSL_CONF=${WOLFPROV_CONFIG}
    
    # Print environment information for debugging
    echo "=== Environment Setup ==="
    echo "WOLFPROV_INSTALL_DIR: $WOLFPROV_INSTALL_DIR"
    echo "WOLFPROV_CONFIG: $WOLFPROV_CONFIG"
    echo "OPENSSL_MODULES: $OPENSSL_MODULES"
    echo "OPENSSL_CONF: $OPENSSL_CONF"
    echo "========================="
}

# Function to check if wolfProvider is properly installed
check_wolfprovider_installation() {
    if [ ! -d "$WOLFPROV_INSTALL_DIR" ]; then
        echo "Error: wolfProvider installation directory not found at $WOLFPROV_INSTALL_DIR"
        echo "Please build and install wolfProvider first or set WOLFPROV_INSTALL_DIR to the correct path"
        return 1
    fi
    
    if [ ! -f "$WOLFPROV_CONFIG" ]; then
        echo "Error: wolfProvider configuration file not found at $WOLFPROV_CONFIG"
        echo "Please set WOLFPROV_CONFIG to the correct path"
        return 1
    fi
    
    return 0
}
