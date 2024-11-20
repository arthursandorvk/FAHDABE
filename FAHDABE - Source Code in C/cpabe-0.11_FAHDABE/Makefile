 top_srcdir = .
prefix = /usr/local
exec_prefix = ${prefix}
bindir = ${exec_prefix}/bin
mandir = ${prefix}/share/man

CC = gcc
CFLAGS  = -O3 -Wall -m64 \
	-I/usr/local/include/glib-2.0 -I/usr/local/lib/glib-2.0/include   \
	-I/usr/include/glib-2.0 -I/usr/lib/i386-linux-gnu/glib-2.0/include -lglib-2.0	\
	-I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -lglib-2.0	 \
	-I/usr/include/pbc -I/usr/local/include/pbc \
	 \
	-DPACKAGE_NAME=\"cpabe\" -DPACKAGE_TARNAME=\"cpabe\" -DPACKAGE_VERSION=\"0.12\" -DPACKAGE_STRING=\"cpabe\ 0.12\" -DPACKAGE_BUGREPORT=\"sandorvoundi@xidian.edu.cn\" -DPACKAGE_URL=\"\" -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -DSTDC_HEADERS=1 -DHAVE_FCNTL_H=1 -DHAVE_STDDEF_H=1 -DHAVE_STRING_H=1 -DHAVE_STDLIB_H=1 -DHAVE_MALLOC=1 -DLSTAT_FOLLOWS_SLASHED_SYMLINK=1 -DHAVE_VPRINTF=1 -DHAVE_LIBCRYPTO=1 -DHAVE_LIBCRYPTO=1 -DHAVE_STRCHR=1 -DHAVE_STRDUP=1 -DHAVE_MEMSET=1 -DHAVE_GMP=1 -DHAVE_PBC=1 -DHAVE_BSWABE=1
LDFLAGS = -O3 -Wall -m64 \
	-L/usr/local/lib -lglib-2.0   \
	-Wl,-rpath /usr/local/lib -lgmp \
	-Wl,-rpath /usr/local/lib -lpbc \
	-lbswabe \
	-lcrypto -lcrypto \
	-lgmp	\
	-lglib-2.0 \
	-ldl \
	-lrt \
	-pthread \
	-lpbc

DISTNAME = cpabe-0.12

TARGETS  = cpabe-setup cpabe-keygen1 cpabe-keygen0 cpabe-hide cpabe-keygen2 cpabe-keygen3 cpabe-keygen4 cpabe-encrypt1 cpabe-encrypt2 cpabe-transform1 cpabe-transform2 cpabe-lthash_benchmark cpabe-benchmark test-lang # cpabe-lthash_benchmark cpabe-benchmark cpabe-DOrevoke_DU cpabe-CSrevoke_DU cpabe-UCNrevoke_DU cpabe-decryptCT_DURev  cpabe-benchmark cpabe-lthash_benchmark  cpabe-hideDUAttr #cpabe-AArevoke_ATTR cpabe-CSrevoke_ATTR cpabe-RRDrevoke_ATTR (no impact on Data owner and Data User)
# cpabe-enc  cpabe-keygen  cpabe-dec  cpabe-keygenDO  cpabe-keygen2  cpabe-integrate cpabe-cloudauth cpabe-Urevocation cpabe-benchmark

DEVTARGS = test-lang TAGS

MANUALS  = $(TARGETS:=.1)
HTMLMANS = $(MANUALS:.1=.html)

all: $(TARGETS) $(DEVTARGS)

# user-level compilation

cpabe-setup: setup.o common.o
	$(CC) -o $@ $^ $(LDFLAGS)

cpabe-keygen0: keygen0.o common.o
	$(CC) -o $@ $^ $(LDFLAGS)

cpabe-keygen1: keygen1.o common.o policy_lang.o
	$(CC) -o $@ $^ $(LDFLAGS)
	
cpabe-keygen2: keygen2.o common.o policy_lang.o
	$(CC) -o $@ $^ $(LDFLAGS)

cpabe-keygen3: keygen3.o common.o policy_lang.o
	$(CC) -o $@ $^ $(LDFLAGS)

cpabe-keygen4: keygen4.o common.o policy_lang.o
	$(CC) -o $@ $^ $(LDFLAGS)	

cpabe-encrypt1: encrypt1.o common.o policy_lang.o
	$(CC) -o $@ $^ $(LDFLAGS)

cpabe-encrypt2: encrypt2.o common.o policy_lang.o
	$(CC) -o $@ $^ $(LDFLAGS)

cpabe-transform1: transform1.o common.o policy_lang.o
	$(CC) -o $@ $^ $(LDFLAGS)

cpabe-transform2: transform2.o common.o
	$(CC) -o $@ $^ $(LDFLAGS)

cpabe-hide:  hide.o common.o
	$(CC) -o $@ $^ $(LDFLAGS)

#-------------------------------------------------------------
#-------- Revocation will be addressed in future Work --------
# ------------------------------------------------------------
#cpabe-AArevoke_ATTR:  AArevoke_ATTR.o common.o policy_lang.o
#	$(CC) -o $@ $^ $(LDFLAGS)

#cpabe-CSrevoke_ATTR: CSRevoke_ATTR.o common.o
#	$(CC) -o $@ $^ $(LDFLAGS)

#cpabe-RRDrevoke_ATTR: UCNrevoke_ATTR.o common.o
#	$(CC) -o $@ $^ $(LDFLAGS)
#------------------------------------------------------------

cpabe-benchmark:benchmark.o common.o policy_lang.o
	$(CC) -o $@ $^ $(LDFLAGS)

cpabe-lthash_benchmark: lthash_benchmark.o common.o policy_lang.o
	$(CC) -o $@ $^ $(LDFLAGS)

test-lang: test-lang.o common.o policy_lang.o
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c *.h Makefile
	$(CC) -c -o $@ $< $(CFLAGS)

#cpabe-keygen: keygen.o common.o policy_lang.o
#	$(CC) -o $@ $^ $(LDFLAGS)
	

#cpabe-integrate: integrate.o common.o policy_lang.o
#	$(CC) -o $@ $^ $(LDFLAGS)

#cpabe-dec: dec.o common.o
#	$(CC) -o $@ $^ $(LDFLAGS)

#cpabe-cloudauth: cloudauth.o common.o policy_lang.o
#	$(CC) -o $@ $^ $(LDFLAGS)


#cpabe-Urevocation: Urevocation.o common.o policy_lang.o
#	$(CC) -o $@ $^ $(LDFLAGS)


# installation

dist: *.y policy_lang.c *.c *.h *.more-man \
	AUTHORS COPYING INSTALL NEWS README $(MANUALS) \
	aclocal.m4 acinclude.m4 configure configure.ac install-sh Makefile.in \
	missing mkinstalldirs
	rm -rf $(DISTNAME)
	mkdir $(DISTNAME)
	cp $^ $(DISTNAME)
	tar zc $(DISTNAME) > $(DISTNAME).tar.gz
	rm -rf $(DISTNAME)

install: $(TARGETS) $(MANUALS)
	$(top_srcdir)/mkinstalldirs -m 755 $(DESTDIR)$(bindir)
	$(top_srcdir)/mkinstalldirs -m 755 $(DESTDIR)$(mandir)
	$(top_srcdir)/mkinstalldirs -m 755 $(DESTDIR)$(mandir)/man1
	for PROG in $(TARGETS); \
	do \
	  $(top_srcdir)/install-sh -m 755 $$PROG   $(DESTDIR)$(bindir); \
	  $(top_srcdir)/install-sh -m 644 $$PROG.1 $(DESTDIR)$(mandir)/man1; \
	done

uninstall:
	for PROG in $(TARGETS); \
	do \
	  /bin/rm -f $(DESTDIR)$(bindir)/$$PROG; \
	  /bin/rm -f $(DESTDIR)$(mandir)/man1/$$PROG.1; \
	done

# developer-level processing and meta stuff

%.c: %.y *.h Makefile
	if which bison 2> /dev/null; then \
	   bison -o $@ $<; \
	fi

%.1: % %.more-man
	if which help2man 2> /dev/null; then \
	   help2man --section=1 --source="SRI International" --no-info \
	            -I $<.more-man -o $@ ./$<; \
	fi

%.html: %.1
	groff -man -Thtml $< > $@

html: $(HTMLMANS)

TAGS: *.c *.h *.y
	@(etags $^ || true) 2> /dev/null

Makefile: Makefile.in config.status
	./config.status

config.status: configure
	./config.status --recheck

configure: configure.ac aclocal.m4 acinclude.m4
	autoconf	

# cleanup

# remove everything an installing user can rebuild
clean:
	rm -f *.o $(TARGETS) $(DEVTARGS) *.tar.gz pub_key master_key priv_key rrd_key DO_key user_key decryption_results du_blind DU_Out_key policy.txt *~

# remove everything a package developer can rebuild
distclean: clean
	rm -rf policy_lang.c autom4te.cache Makefile config.status config.log config.cache \
		configure configure.scan autoscan*.log *.1 *.html *.lineno

