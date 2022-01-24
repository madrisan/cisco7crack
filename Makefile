CC      ?=gcc
CFLAGS  ?=-fPIE -fstack-protector-strong -Wformat -Werror=format-security -Wall -pedantic -Wdate-time -D_FORTIFY_SOURCE=2
LDFLAGS ?=-fPIE -pie -Wl,-z,relro -Wl,-z,now -Wl,--as-needed
PREFIX  ?=/usr
PROG=cisco7crack
OBJS=$(patsubst %.c, %.o, $(sort $(wildcard *.c)))
HEADERS=$(wildcard *.h)

all: $(PROG)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(PROG): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $@

clean:
	rm -f *.o
	rm -f $(PROG)

DESTBINDIR = $(DESTDIR)$(PREFIX)/bin
install: all
	if [ ! -d $(DESTBINDIR) ] ; then \
		mkdir -p $(DESTBINDIR) ; \
	fi
	install -m755 $(PROG) $(DESTBINDIR)/

uninstall:
	rm $(DESTBINDIR)/$(PROG)
