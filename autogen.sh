#!/bin/sh

if [ USER != 'root']; then
	echo 'Script must be run as root'
	exit 1
fi

if [ ! -d "m4" ]; then
	mkdir m4
fi

if [ uname == 'FreeBSD' ]; then
	pkg install devel/autoconf devel/libtool devel/openssl-devel
elif [ uname | grep 'Linux debian' !=  '' ]; then
	apt install -y autoconf libtool openssl-devel
else 
	echo 'OS not supported, compile it manually'
	exit 1
fi

autoreconf -ivf
./configure --prefix=/usr
make install


