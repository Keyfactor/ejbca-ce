##----------------------------------------------------------------------------
# Created with genmake.pl v1.1 on Wed Jun 28 22:17:05 2006
# genmake.pl home: http://muquit.com/muquit/software/
# Copryright: GNU GPL (http://www.gnu.org/copyleft/gpl.html)
##----------------------------------------------------------------------------
rm=/bin/rm -f
CC= cc
DEFS=  
PROGNAME= change_p12_pwd
INCLUDES=  -I.
LIBS=/usr/lib/libcrypto.so /usr/lib/libssl.so


DEFINES= $(INCLUDES) $(DEFS) -DSYS_UNIX=1
CFLAGS= -g $(DEFINES)

SRCS = change_p12_pwd.c 

OBJS = change_p12_pwd.o 

.c.o:
	$(rm) $@
	$(CC) $(CFLAGS) -c $*.c

all: $(PROGNAME)

$(PROGNAME) : $(OBJS)
	$(CC) $(CFLAGS) -o $(PROGNAME) $(OBJS) $(LIBS)

clean:
	$(rm) $(OBJS) $(PROGNAME) core *~
