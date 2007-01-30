# Makefile for systems with GNU tools
CC 	=	gcc
INSTALL	=	install
IFLAGS  = -idirafter dummyinc
#CFLAGS = -g
CFLAGS	=	-I include/sqlite -g -Wall -W -Wshadow #-pedantic -Werror -Wconversion

LIBS	=	`./vsf_findlibs.sh`
LINK	=	-Llib/sqlite/cygwin -lsqlite3 # -Wl,-s

OBJS	=	main.o utility.o prelogin.o ftpcmdio.o postlogin.o privsock.o \
		tunables.o ftpdataio.o secbuf.o ls.o \
		postprivparent.o logging.o str.o netstr.o sysstr.o strlist.o \
    banner.o filestr.o parseconf.o secutil.o \
    ascii.o oneprocess.o twoprocess.o privops.o standalone.o hash.o \
    tcpwrap.o ipaddrparse.o access.o features.o readwrite.o \
    ssl.o sysutil.o sysdeputil.o db.o crc32.o rfc1413.o md5.o


.c.o:
	$(CC) -c $*.c $(CFLAGS) $(IFLAGS)

vsftpd: $(OBJS) 
	$(CC) -o vsftpd $(OBJS) $(LINK) $(LIBS) $(LDFLAGS)

all: vsftpd
	
install:
	if [ -x /usr/local/sbin ]; then \
		$(INSTALL) -m 755 vsftpd /usr/local/sbin/vsftpd; \
	else \
		$(INSTALL) -m 755 vsftpd /usr/sbin/vsftpd; fi
	if [ -x /usr/local/man ]; then \
		$(INSTALL) -m 644 vsftpd.8 /usr/local/man/man8/vsftpd.8; \
		$(INSTALL) -m 644 vsftpd.conf.5 /usr/local/man/man5/vsftpd.conf.5; \
	elif [ -x /usr/share/man ]; then \
		$(INSTALL) -m 644 vsftpd.8 /usr/share/man/man8/vsftpd.8; \
		$(INSTALL) -m 644 vsftpd.conf.5 /usr/share/man/man5/vsftpd.conf.5; \
	else \
		$(INSTALL) -m 644 vsftpd.8 /usr/man/man8/vsftpd.8; \
		$(INSTALL) -m 644 vsftpd.conf.5 /usr/man/man5/vsftpd.conf.5; fi
	if [ -x /etc/xinetd.d ]; then \
		$(INSTALL) -m 644 xinetd.d/vsftpd /etc/xinetd.d/vsftpd; fi

clean:
	rm -f *.o *.swp vsftpd vsftpd.exe
