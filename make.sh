#!/bin/bash

CUR_DIR=`pwd`

make clean

#This is a typical issue with 4.06.0 since the default has switched from unsafe-string to safe-string
export OCAMLPARAM="safe-string=0,_"
make DEBUG=1
make sdk_install_pkg DEBUG=1
make psw_install_pkg DEBUG=1

cd /opt/intel/sgxsdk
./uninstall.sh
cd /opt/intel/sgxpsw
./uninstall.sh


cd $CUR_DIR
./linux/installer/bin/sgx_linux_x64_psw_2.1.42002.bin
./linux/installer/bin/sgx_linux_x64_sdk_2.1.42002.bin


