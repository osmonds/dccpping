###############################################################################
#Author: Samuel Jero <sj323707@ohio.edu>
#
# Date: 12/2012
#
# Makefile for program dccpping
###############################################################################

CFLAGS= -O2 -Wall -Werror -g --std=gnu99

CC = gcc

BINDIR = /usr/local/bin
MANDIR = /usr/local/man

all: dccpping dccpping.1

dccpping: dccpping.c checksums.h checksums.o Makefile
	${CC} ${CFLAGS}  dccpping.c checksums.o -odccpping
	
checksums.o: checksums.c checksums.h Makefile
	${CC} ${CFLAGS} -c checksums.c -ochecksums.o

dccpping.1: dccpping.pod
	pod2man -s 1 -c "dccpping" dccpping.pod > dccpping.1

install: dccpping dccpping.1
	install -m 4755 -o root -g root dccpping ${BINDIR}/dccpping
	install -m 444 -o bin -g bin dccpping.1 ${MANDIR}/man1/dccpping.1

uninstall:
	rm -f ${BINDIR}/dccpping
	rm -f ${MANDIR}/man1/dccpping.1

clean:
	rm -f *~ dccpping core *.o dccpping.1
