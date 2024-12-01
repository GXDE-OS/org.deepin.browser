#!/bin/sh

export AR=ar  
export NM=nm  
export CC=clang  
export CXX=clang++

ninja -C out/Release chrome
