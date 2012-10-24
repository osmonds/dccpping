###############################################################################
#Author: Samuel Jero <sj323707@ohio.edu>
#
# Date: 11/2011
#
# Makefile for program dccpping
###############################################################################

CFLAGS= -O2 -Wall -Werror -g --std=gnu99

# for solaris, you probably want:
#	LDLIBS = -lnsl -lsocket
# for HP, I'm told that you need:
#	LDLIBS = -lstr
# everybody else (that I know of) just needs:
#	LDLIBS =
LDLIBS =

CC = gcc

BINDIR = /usr/local/bin
MANDIR = /usr/local/man

all: dccpping

dccpping: dccpping.c
	${CC} ${CFLAGS} ${LDLIBS}  dccpping.c -odccpping


install: dccpping
	install -m 755 -o bin -g bin dccp2tcp ${BINDIR}/dccpping
#	install -m 444 -o bin -g bin dccp2tcp.1 ${MANDIR}/man1/dccpping.1

uninstall:
	rm -f ${BINDIR}/dccpping
#	rm -r ${MANDIR}/man1/dccpping.1

clean:
	rm -f *~ dccpping core *.o