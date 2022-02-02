#!/bin/sh

VERSION=$(keeper_ansible --version | awk -v FS="(Plugin Version: |\n)" '{print $2}' | tr -cd '[:alnum:]._-')
if [ -z "$VERSION" ]; then
    echo "Cannot find version from installed module."
    exit 1
fi
echo $VERSION