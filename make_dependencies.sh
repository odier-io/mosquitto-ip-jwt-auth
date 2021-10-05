#!/bin/bash

########################################################################################################################

L8W8JWT_VERSION=2.0.0

########################################################################################################################

THIS_SCRIPT=${BASH_SOURCE[0]:-$0}

while [[ "$(readlink $THIS_SCRIPT)" != "" ]]
do
  THIS_SCRIPT=$(readlink $THIS_SCRIPT)
done

MOSQUITTO_AMI_HOME=$(cd "$(dirname $THIS_SCRIPT)" && pwd)

########################################################################################################################

echo ''
echo '#############################################################################'
echo '# Compiling L8W8JWT...                                                      #'
echo '#############################################################################'
echo ''

########################################################################################################################

rm -fr $MOSQUITTO_AMI_HOME/l8w8jwt/

########################################################################################################################

if [[ 0 == 0 ]]
then
(
  ######################################################################################################################

  git clone --recurse-submodules https://github.com/GlitchedPolygons/l8w8jwt.git --branch $L8W8JWT_VERSION $MOSQUITTO_AMI_HOME/l8w8jwt

  ######################################################################################################################

  mkdir $MOSQUITTO_AMI_HOME/l8w8jwt/build
  cd $MOSQUITTO_AMI_HOME/l8w8jwt/build

  CFLAGS='-fPIC -Wno-unused-result' cmake -DBUILD_SHARED_LIBS=Off -DL8W8JWT_PACKAGE=On -DL8W8JWT_ENABLE_EDDSA=On -DCMAKE_BUILD_TYPE=Release ..

  cmake --build . --config Release -j 2

  ######################################################################################################################

  mkdir -p $MOSQUITTO_AMI_HOME/lib/
  mkdir -p $MOSQUITTO_AMI_HOME/include/l8w8jwt/

  cp $MOSQUITTO_AMI_HOME/l8w8jwt/build/mbedtls/library/libmbedcrypto.a $MOSQUITTO_AMI_HOME/lib/
  cp $MOSQUITTO_AMI_HOME/l8w8jwt/build/mbedtls/library/libmbedtls.a $MOSQUITTO_AMI_HOME/lib/
  cp $MOSQUITTO_AMI_HOME/l8w8jwt/build/mbedtls/library/libmbedx509.a $MOSQUITTO_AMI_HOME/lib/
  cp $MOSQUITTO_AMI_HOME/l8w8jwt/build/l8w8jwt/bin/release/libl8w8jwt.a $MOSQUITTO_AMI_HOME/lib/

  cp -R $MOSQUITTO_AMI_HOME/l8w8jwt/build/l8w8jwt/include/l8w8jwt/*.h $MOSQUITTO_AMI_HOME/include/l8w8jwt/

  ######################################################################################################################
) || exit 1
fi

########################################################################################################################

rm -fr $MOSQUITTO_AMI_HOME/l8w8jwt/

########################################################################################################################

