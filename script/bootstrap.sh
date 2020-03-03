#!/bin/bash
#
#  Copyright (c) 2019, The OpenThread Registrar Authors.
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#  3. Neither the name of the copyright holder nor the
#     names of its contributors may be used to endorse or promote products
#     derived from this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#  POSSIBILITY OF SUCH DAMAGE.
#

set -e

ACE_REPO=https://bitbucket.org/marco-tiloca-sics/ace-java

## Test if we has the given command.
## Args: $1, the command.
has_command() {
    local cmd=$1
    command -v $cmd > /dev/null 2>&1
}

install_toolchain() {
    if [ $(uname) = "Linux" ]; then
        echo "OS is Linux"
        has_command java || {
            sudo apt-get update
            sudo apt-get install default-jre default-jdk -y
        }
        has_command mvn || {
            sudo apt-get update
            sudo apt-get install maven -y
        }
    elif [ $(uname) = "Darwin" ]; then
        echo "OS is Darwin"
        has_command java || brew cask install java
        has_command mvn || brew install maven
    else
        echo "platform $(uname) is not fully supported"
        exit 1
    fi
    java -version
    mvn -verion
}

install_ace() {
    if [ ! -d ace ]; then
        git clone $ACE_REPO ace
    fi
    cd ace
        mvn -DskipTests install
    cd -
    rm -rf ace
}

install_toolchain
install_ace
