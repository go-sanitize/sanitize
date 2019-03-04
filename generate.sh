#!/bin/bash

# Quick way to copy content of one file to another, replacing the data type

SRC=${1}
TGT=${2}

FILE=${SRC}.go
FILE_TEST=${SRC}_test.go

TARGET=${TGT}.go
TARGET_TEST=${TGT}_test.go

if [ ! -f ${FILE} ]; then
    echo "${FILE} does not exist"
    exit 1
fi
if [ ! -f ${FILE_TEST} ]; then
    echo "${FILE_TEST} does not exist"
    exit 1
fi
if [ -z ${TGT} ]; then
    echo "provide a target type"
    exit 1
fi

cat "${FILE}" | sed "s/${SRC}/${TGT}/" | sed "s/${SRC^}/${TGT^}/" > "${TARGET}"
cat "${FILE_TEST}" | sed "s/${SRC}/${TGT}/" | sed "s/${SRC^}/${TGT^}/" > "${TARGET_TEST}"

