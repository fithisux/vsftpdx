# Makefile for systems with GNU tools
CC 	=	gcc
AR      =       ar
INSTALL	=	install
IFLAGS  = 
PREFIX  = ../vsftpdx
#CFLAGS = -g
CFLAGS	=	-I $(PREFIX)/include/sqlite -I $(PREFIX)/include/lua -g -Wall -W -Wshadow #-pedantic -Werror -Wconversion

LIBS	=	`./vsf_findlibs.sh`
LINK	=	-L$(PREFIX)/lib/sqlite/cygwin -L$(PREFIX)/lib/lua/cygwin -lsqlite3 -llua51 # -Wl,-s

OBJS	=	tchest.o


.c.o:
	$(CC) -c $*.c $(CFLAGS) $(IFLAGS)

tchest: $(OBJS) 
	$(AR) rcs libtchest.a $(OBJS)

all: tchest
	

clean:
	rm -f *.o *.swp libtchest.a
