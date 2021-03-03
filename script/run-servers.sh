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

readonly DOMAIN_NAME=TestDomainTCE

readonly TIMESTAMP=$(date "+%Y-%m-%d-%H.%M.%S")
readonly LOGS=logs/${TIMESTAMP}
readonly TRI_LOG=${LOGS}/tri.log
readonly REGISTRAR_LOG=${LOGS}/registrar.log
readonly MASA_LOG=${LOGS}/masa.log

readonly TRI_PORT=5683
readonly REGISTRAR_PORT=5684
readonly MASA_PORT=5685
#readonly BORDER_AGENT_PORT=61631

readonly JAR_FILE=./target/ot-registrar-0.1-SNAPSHOT-jar-with-dependencies.jar
# prebuilt TRI v1.2 server from the tce-registrar-java BitBucket repo
readonly JAR_TRI=./script/TRIserver.jar

#readonly CREDENTIAL=credentials/threadgroup-5f9d307c.p12
readonly CREDENTIAL=credentials/local-masa/test_credentials.p12

rm -rf $LOGS
mkdir -p $LOGS

echo "starting TRI, port=${TRI_PORT}, log=${TRI_LOG}..."
java -jar $JAR_TRI [::1] $REGISTRAR_PORT -log $TRI_LOG >> /dev/null 2>&1 &
exit

echo "starting registrar server, port=${REGISTRAR_PORT}, log=${REGISTRAR_LOG}..."
java -cp $JAR_FILE \
    com.google.openthread.registrar.RegistrarMain \
    -v -d $DOMAIN_NAME -p $REGISTRAR_PORT -f $CREDENTIAL \
    >> $REGISTRAR_LOG 2>&1 &

echo "starting masa server, port=${MASA_PORT}, log=${MASA_LOG}..."
java -cp $JAR_FILE \
    com.google.openthread.masa.MASAMain \
    -p $MASA_PORT -f $CREDENTIAL \
    >> $MASA_LOG 2>&1 &
