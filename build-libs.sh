#!/bin/sh

cd rpmvercmp

# This are the commands for each EL version
# Needs to be tested

# EL5
make
cc /usr/lib64/librpm-4.4.so rpmvercm p.o   -o rpmvercmp
cp rpmvercmp rpmvercmp.el5
cp rpmvercmp.el5 ..

#EL6
make
cp rpmvercmp rpmvercmp.el6
cp rpmvercmp.el6 ..

#EL7
cc    -c -o rpmvercmp.o rpmvercmp.c
cc /usr/lib64/librpm.so.3 rpmvercmp.o -o rpmvercmp.el7
cp rpmvercmp.el7 ..

#EL8
cc    -c -o rpmvercmp.o rpmvercmp.c
cc /usr/lib64/librpm.so.8 rpmvercmp.o -o rpmvercmp.el8
cp rpmvercmp.el8 ..

cd ..
