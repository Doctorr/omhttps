# Makefile.in generated by automake 1.13.4 from Makefile.am.
# contrib/omhttps/Makefile.  Generated from Makefile.in by configure.

# Copyright (C) 1994-2013 Free Software Foundation, Inc.

# This Makefile.in is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.




am__is_gnu_make = test -n '$(MAKEFILE_LIST)' && test -n '$(MAKELEVEL)'
am__make_running_with_option = \
  case $${target_option-} in \
      ?) ;; \
      *) echo "am__make_running_with_option: internal error: invalid" \
              "target option '$${target_option-}' specified" >&2; \
         exit 1;; \
  esac; \
  has_opt=no; \
  sane_makeflags=$$MAKEFLAGS; \
  if $(am__is_gnu_make); then \
    sane_makeflags=$$MFLAGS; \
  else \
    case $$MAKEFLAGS in \
      *\\[\ \	]*) \
        bs=\\; \
        sane_makeflags=`printf '%s\n' "$$MAKEFLAGS" \
          | sed "s/$$bs$$bs[$$bs $$bs	]*//g"`;; \
    esac; \
  fi; \
  skip_next=no; \
  strip_trailopt () \
  { \
    flg=`printf '%s\n' "$$flg" | sed "s/$$1.*$$//"`; \
  }; \
  for flg in $$sane_makeflags; do \
    test $$skip_next = yes && { skip_next=no; continue; }; \
    case $$flg in \
      *=*|--*) continue;; \
        -*I) strip_trailopt 'I'; skip_next=yes;; \
      -*I?*) strip_trailopt 'I';; \
        -*O) strip_trailopt 'O'; skip_next=yes;; \
      -*O?*) strip_trailopt 'O';; \
        -*l) strip_trailopt 'l'; skip_next=yes;; \
      -*l?*) strip_trailopt 'l';; \
      -[dEDm]) skip_next=yes;; \
      -[JT]) skip_next=yes;; \
    esac; \
    case $$flg in \
      *$$target_option*) has_opt=yes; break;; \
    esac; \
  done; \
  test $$has_opt = yes
am__make_dryrun = (target_option=n; $(am__make_running_with_option))
am__make_keepgoing = (target_option=k; $(am__make_running_with_option))
pkgdatadir = $(datadir)/rsyslog
pkgincludedir = $(includedir)/rsyslog
pkglibdir = $(libdir)/rsyslog
pkglibexecdir = $(libexecdir)/rsyslog
am__cd = CDPATH="$${ZSH_VERSION+.}$(PATH_SEPARATOR)" && cd
install_sh_DATA = $(install_sh) -c -m 644
install_sh_PROGRAM = $(install_sh) -c
install_sh_SCRIPT = $(install_sh) -c
INSTALL_HEADER = $(INSTALL_DATA)
transform = $(program_transform_name)
NORMAL_INSTALL = :
PRE_INSTALL = :
POST_INSTALL = :
NORMAL_UNINSTALL = :
PRE_UNINSTALL = :
POST_UNINSTALL = :
build_triplet = x86_64-unknown-linux-gnu
host_triplet = x86_64-unknown-linux-gnu
subdir = contrib/omhttps
DIST_COMMON = $(srcdir)/Makefile.in $(srcdir)/Makefile.am \
	$(top_srcdir)/depcomp
ACLOCAL_M4 = $(top_srcdir)/aclocal.m4
am__aclocal_m4_deps = $(top_srcdir)/m4/ac_check_define.m4 \
	$(top_srcdir)/m4/atomic_operations.m4 \
	$(top_srcdir)/m4/atomic_operations_64bit.m4 \
	$(top_srcdir)/m4/libtool.m4 $(top_srcdir)/m4/ltoptions.m4 \
	$(top_srcdir)/m4/ltsugar.m4 $(top_srcdir)/m4/ltversion.m4 \
	$(top_srcdir)/m4/lt~obsolete.m4 $(top_srcdir)/configure.ac
am__configure_deps = $(am__aclocal_m4_deps) $(CONFIGURE_DEPENDENCIES) \
	$(ACLOCAL_M4)
mkinstalldirs = $(install_sh) -d
CONFIG_HEADER = $(top_builddir)/config.h
CONFIG_CLEAN_FILES =
CONFIG_CLEAN_VPATH_FILES =
am__vpath_adj_setup = srcdirstrip=`echo "$(srcdir)" | sed 's|.|.|g'`;
am__vpath_adj = case $$p in \
    $(srcdir)/*) f=`echo "$$p" | sed "s|^$$srcdirstrip/||"`;; \
    *) f=$$p;; \
  esac;
am__strip_dir = f=`echo $$p | sed -e 's|^.*/||'`;
am__install_max = 40
am__nobase_strip_setup = \
  srcdirstrip=`echo "$(srcdir)" | sed 's/[].[^$$\\*|]/\\\\&/g'`
am__nobase_strip = \
  for p in $$list; do echo "$$p"; done | sed -e "s|$$srcdirstrip/||"
am__nobase_list = $(am__nobase_strip_setup); \
  for p in $$list; do echo "$$p $$p"; done | \
  sed "s| $$srcdirstrip/| |;"' / .*\//!s/ .*/ ./; s,\( .*\)/[^/]*$$,\1,' | \
  $(AWK) 'BEGIN { files["."] = "" } { files[$$2] = files[$$2] " " $$1; \
    if (++n[$$2] == $(am__install_max)) \
      { print $$2, files[$$2]; n[$$2] = 0; files[$$2] = "" } } \
    END { for (dir in files) print dir, files[dir] }'
am__base_list = \
  sed '$$!N;$$!N;$$!N;$$!N;$$!N;$$!N;$$!N;s/\n/ /g' | \
  sed '$$!N;$$!N;$$!N;$$!N;s/\n/ /g'
am__uninstall_files_from_dir = { \
  test -z "$$files" \
    || { test ! -d "$$dir" && test ! -f "$$dir" && test ! -r "$$dir"; } \
    || { echo " ( cd '$$dir' && rm -f" $$files ")"; \
         $(am__cd) "$$dir" && rm -f $$files; }; \
  }
am__installdirs = "$(DESTDIR)$(pkglibdir)"
LTLIBRARIES = $(pkglib_LTLIBRARIES)
am__DEPENDENCIES_1 =
omhttps_la_DEPENDENCIES = $(am__DEPENDENCIES_1) $(am__DEPENDENCIES_1)
am_omhttps_la_OBJECTS = omhttps_la-omhttps.lo
omhttps_la_OBJECTS = $(am_omhttps_la_OBJECTS)
AM_V_lt = $(am__v_lt_$(V))
am__v_lt_ = $(am__v_lt_$(AM_DEFAULT_VERBOSITY))
am__v_lt_0 = --silent
am__v_lt_1 = 
omhttps_la_LINK = $(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
	$(LIBTOOLFLAGS) --mode=link $(CCLD) $(AM_CFLAGS) $(CFLAGS) \
	$(omhttps_la_LDFLAGS) $(LDFLAGS) -o $@
AM_V_P = $(am__v_P_$(V))
am__v_P_ = $(am__v_P_$(AM_DEFAULT_VERBOSITY))
am__v_P_0 = false
am__v_P_1 = :
AM_V_GEN = $(am__v_GEN_$(V))
am__v_GEN_ = $(am__v_GEN_$(AM_DEFAULT_VERBOSITY))
am__v_GEN_0 = @echo "  GEN     " $@;
am__v_GEN_1 = 
AM_V_at = $(am__v_at_$(V))
am__v_at_ = $(am__v_at_$(AM_DEFAULT_VERBOSITY))
am__v_at_0 = @
am__v_at_1 = 
DEFAULT_INCLUDES = -I. -I$(top_builddir)
depcomp = $(SHELL) $(top_srcdir)/depcomp
am__depfiles_maybe = depfiles
am__mv = mv -f
COMPILE = $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	$(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)
LTCOMPILE = $(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
	$(LIBTOOLFLAGS) --mode=compile $(CC) $(DEFS) \
	$(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) \
	$(AM_CFLAGS) $(CFLAGS)
AM_V_CC = $(am__v_CC_$(V))
am__v_CC_ = $(am__v_CC_$(AM_DEFAULT_VERBOSITY))
am__v_CC_0 = @echo "  CC      " $@;
am__v_CC_1 = 
CCLD = $(CC)
LINK = $(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
	$(LIBTOOLFLAGS) --mode=link $(CCLD) $(AM_CFLAGS) $(CFLAGS) \
	$(AM_LDFLAGS) $(LDFLAGS) -o $@
AM_V_CCLD = $(am__v_CCLD_$(V))
am__v_CCLD_ = $(am__v_CCLD_$(AM_DEFAULT_VERBOSITY))
am__v_CCLD_0 = @echo "  CCLD    " $@;
am__v_CCLD_1 = 
SOURCES = $(omhttps_la_SOURCES)
DIST_SOURCES = $(omhttps_la_SOURCES)
am__can_run_installinfo = \
  case $$AM_UPDATE_INFO_DIR in \
    n|no|NO) false;; \
    *) (install-info --version) >/dev/null 2>&1;; \
  esac
am__tagged_files = $(HEADERS) $(SOURCES) $(TAGS_FILES) $(LISP)
# Read a list of newline-separated strings from the standard input,
# and print each of them once, without duplicates.  Input order is
# *not* preserved.
am__uniquify_input = $(AWK) '\
  BEGIN { nonempty = 0; } \
  { items[$$0] = 1; nonempty = 1; } \
  END { if (nonempty) { for (i in items) print i; }; } \
'
# Make sure the list of sources is unique.  This is necessary because,
# e.g., the same source file might be shared among _SOURCES variables
# for different programs/libraries.
am__define_uniq_tagged_files = \
  list='$(am__tagged_files)'; \
  unique=`for i in $$list; do \
    if test -f "$$i"; then echo $$i; else echo $(srcdir)/$$i; fi; \
  done | $(am__uniquify_input)`
ETAGS = etags
CTAGS = ctags
DISTFILES = $(DIST_COMMON) $(DIST_SOURCES) $(TEXINFOS) $(EXTRA_DIST)
ACLOCAL = ${SHELL} /home/rdoctor/rsyslog-8.20.0/missing aclocal-1.13
AMTAR = $${TAR-tar}
AM_DEFAULT_VERBOSITY = 0
AR = ar
AUTOCONF = ${SHELL} /home/rdoctor/rsyslog-8.20.0/missing autoconf
AUTOHEADER = ${SHELL} /home/rdoctor/rsyslog-8.20.0/missing autoheader
AUTOMAKE = ${SHELL} /home/rdoctor/rsyslog-8.20.0/missing automake-1.13
AWK = gawk
CC = gcc -std=gnu99
CCDEPMODE = depmode=gcc3
CFLAGS = -g -O2
CPP = gcc -E
CPPFLAGS = 
CURL_CFLAGS =  
CURL_LIBS = -lcurl  
CYGPATH_W = echo
CZMQ_CFLAGS = 
CZMQ_LIBS = 
DEFS = -DHAVE_CONFIG_H
DEPDIR = .deps
DLLTOOL = false
DL_LIBS = -ldl 
DSYMUTIL = 
DUMPBIN = 
ECHO_C = 
ECHO_N = -n
ECHO_T = 
EGREP = /usr/bin/grep -E
EXEEXT = 
FGREP = /usr/bin/grep -F
GLIB_CFLAGS = 
GLIB_LIBS = 
GNUTLS_CFLAGS = 
GNUTLS_LIBS = 
GREP = /usr/bin/grep
GSS_LIBS = 
GT_KSI_CFLAGS = 
GT_KSI_LIBS = 
GUARDTIME_CFLAGS = 
GUARDTIME_LIBS = 
HIREDIS_CFLAGS = 
HIREDIS_LIBS = 
IMUDP_LIBS = 
INSTALL = /usr/bin/install -c
INSTALL_DATA = ${INSTALL} -m 644
INSTALL_PROGRAM = ${INSTALL}
INSTALL_SCRIPT = ${INSTALL}
INSTALL_STRIP_PROGRAM = $(install_sh) -c -s
JSON_C_CFLAGS = -I/usr/include/libfastjson  
JSON_C_LIBS = -lfastjson  
LD = /usr/bin/ld -m elf_x86_64
LDFLAGS = 
LEX = flex
LEXLIB = 
LEX_OUTPUT_ROOT = lex.yy
LIBDBI_CFLAGS = 
LIBDBI_LIBS = 
LIBESTR_CFLAGS =  
LIBESTR_LIBS = -lestr  
LIBGCRYPT_CFLAGS = 
LIBGCRYPT_CONFIG = /usr/bin/libgcrypt-config
LIBGCRYPT_LIBS = -lgcrypt -ldl -lgpg-error
LIBLOGGING_CFLAGS = 
LIBLOGGING_LIBS = 
LIBLOGGING_STDLOG_CFLAGS =  
LIBLOGGING_STDLOG_LIBS = -llogging-stdlog  
LIBLOGNORM_CFLAGS = 
LIBLOGNORM_LIBS = 
LIBM = -lm
LIBMONGO_CLIENT_CFLAGS = 
LIBMONGO_CLIENT_LIBS = 
LIBOBJS = 
LIBRDKAFKA_CFLAGS = 
LIBRDKAFKA_LIBS = 
LIBS = 
LIBSYSTEMD_JOURNAL_CFLAGS = 
LIBSYSTEMD_JOURNAL_LIBS = 
LIBTOOL = $(SHELL) $(top_builddir)/libtool
LIBUUID_CFLAGS = 
LIBUUID_LIBS = 
LIPO = 
LN_S = ln -s
LTLIBOBJS = 
MAKEINFO = ${SHELL} /home/rdoctor/rsyslog-8.20.0/missing makeinfo
MANIFEST_TOOL = :
MKDIR_P = /usr/bin/mkdir -p
MYSQL_CFLAGS = 
MYSQL_CONFIG = 
MYSQL_LIBS = 
NM = /usr/bin/nm -B
NMEDIT = 
OBJDUMP = objdump
OBJEXT = o
OPENSSL_CFLAGS = 
OPENSSL_LIBS = 
OTOOL = 
OTOOL64 = 
PACKAGE = rsyslog
PACKAGE_BUGREPORT = rsyslog@lists.adiscon.com
PACKAGE_NAME = rsyslog
PACKAGE_STRING = rsyslog 8.20.0
PACKAGE_TARNAME = rsyslog
PACKAGE_URL = 
PACKAGE_VERSION = 8.20.0
PATH_SEPARATOR = :
PGSQL_CFLAGS = 
PGSQL_LIBS = 
PG_CONFIG = 
PKG_CONFIG = /usr/bin/pkg-config
PKG_CONFIG_LIBDIR = 
PKG_CONFIG_PATH = 
PROTON_CFLAGS = 
PROTON_LIBS = 
PTHREADS_CFLAGS = -pthread
PTHREADS_LIBS = -lpthread
RABBITMQ_CFLAGS = 
RABBITMQ_LIBS = 
RANLIB = ranlib
READLINK = 
RELP_CFLAGS = 
RELP_LIBS = 
RSRT_CFLAGS = $(RSRT_CFLAGS1) $(LIBESTR_CFLAGS) $(JSON_C_CFLAGS) -W -Wall -Wformat-security -Wshadow -Wcast-align -Wpointer-arith -Wmissing-format-attribute -Werror=implicit-function-declaration -g 
RSRT_CFLAGS1 = -I$(top_srcdir)/runtime -I$(top_srcdir) -I$(top_srcdir)/grammar
RSRT_LIBS = $(RSRT_LIBS1) $(LIBESTR_LIBS) $(JSON_C_LIBS)
RSRT_LIBS1 = $(top_builddir)/runtime/librsyslog.la
RST2MAN = false
RT_LIBS =  -lrt 
SED = /usr/bin/sed
SET_MAKE = 
SHELL = /bin/sh
SNMP_CFLAGS = 
SNMP_LIBS = 
SOL_LIBS = 
STRIP = strip
UDPSPOOF_CFLAGS = 
UDPSPOOF_LIBS = 
VALGRIND = valgrind
VERSION = 8.20.0
WGET = 
YACC = bison -y
YACC_FOUND = 
YFLAGS = 
ZLIB_CFLAGS =  
ZLIB_LIBS = -lz  
abs_builddir = /home/rdoctor/rsyslog-8.20.0/contrib/omhttps
abs_srcdir = /home/rdoctor/rsyslog-8.20.0/contrib/omhttps
abs_top_builddir = /home/rdoctor/rsyslog-8.20.0
abs_top_srcdir = /home/rdoctor/rsyslog-8.20.0
ac_ct_AR = ar
ac_ct_CC = gcc
ac_ct_DUMPBIN = 
am__include = include
am__leading_dot = .
am__quote = 
am__tar = $${TAR-tar} chof - "$$tardir"
am__untar = $${TAR-tar} xf -
bindir = ${exec_prefix}/bin
build = x86_64-unknown-linux-gnu
build_alias = 
build_cpu = x86_64
build_os = linux-gnu
build_vendor = unknown
builddir = .
datadir = ${datarootdir}
datarootdir = ${prefix}/share
docdir = ${datarootdir}/doc/${PACKAGE_TARNAME}
dvidir = ${docdir}
exec_prefix = ${prefix}
host = x86_64-unknown-linux-gnu
host_alias = 
host_cpu = x86_64
host_os = linux-gnu
host_vendor = unknown
htmldir = ${docdir}
includedir = ${prefix}/include
infodir = ${datarootdir}/info
install_sh = ${SHELL} /home/rdoctor/rsyslog-8.20.0/install-sh
libdir = ${exec_prefix}/lib
libexecdir = ${exec_prefix}/libexec
localedir = ${datarootdir}/locale
localstatedir = ${prefix}/var
mandir = ${datarootdir}/man
mkdir_p = $(MKDIR_P)
moddirs = 
oldincludedir = /usr/include
pdfdir = ${docdir}
prefix = /usr
program_transform_name = s,x,x,
psdir = ${docdir}
sbindir = ${exec_prefix}/sbin
sharedstatedir = ${prefix}/com
srcdir = .
sysconfdir = ${prefix}/etc
systemdsystemunitdir = /usr/lib/systemd/system
target_alias = 
top_build_prefix = ../../
top_builddir = ../..
top_srcdir = ../..
pkglib_LTLIBRARIES = omhttps.la
omhttps_la_SOURCES = omhttps.c
omhttps_la_CPPFLAGS = $(RSRT_CFLAGS) $(PTHREADS_CFLAGS) $(CURL_CFLAGS) $(JSON_C_CFLAGS)
omhttps_la_LDFLAGS = -module -avoid-version
omhttps_la_LIBADD = $(CURL_LIBS) $(JSON_C_LIBS)
EXTRA_DIST = 
all: all-am

.SUFFIXES:
.SUFFIXES: .c .lo .o .obj
$(srcdir)/Makefile.in:  $(srcdir)/Makefile.am  $(am__configure_deps)
	@for dep in $?; do \
	  case '$(am__configure_deps)' in \
	    *$$dep*) \
	      ( cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh ) \
	        && { if test -f $@; then exit 0; else break; fi; }; \
	      exit 1;; \
	  esac; \
	done; \
	echo ' cd $(top_srcdir) && $(AUTOMAKE) --gnu contrib/omhttps/Makefile'; \
	$(am__cd) $(top_srcdir) && \
	  $(AUTOMAKE) --gnu contrib/omhttps/Makefile
.PRECIOUS: Makefile
Makefile: $(srcdir)/Makefile.in $(top_builddir)/config.status
	@case '$?' in \
	  *config.status*) \
	    cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh;; \
	  *) \
	    echo ' cd $(top_builddir) && $(SHELL) ./config.status $(subdir)/$@ $(am__depfiles_maybe)'; \
	    cd $(top_builddir) && $(SHELL) ./config.status $(subdir)/$@ $(am__depfiles_maybe);; \
	esac;

$(top_builddir)/config.status: $(top_srcdir)/configure $(CONFIG_STATUS_DEPENDENCIES)
	cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh

$(top_srcdir)/configure:  $(am__configure_deps)
	cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh
$(ACLOCAL_M4):  $(am__aclocal_m4_deps)
	cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh
$(am__aclocal_m4_deps):

install-pkglibLTLIBRARIES: $(pkglib_LTLIBRARIES)
	@$(NORMAL_INSTALL)
	@list='$(pkglib_LTLIBRARIES)'; test -n "$(pkglibdir)" || list=; \
	list2=; for p in $$list; do \
	  if test -f $$p; then \
	    list2="$$list2 $$p"; \
	  else :; fi; \
	done; \
	test -z "$$list2" || { \
	  echo " $(MKDIR_P) '$(DESTDIR)$(pkglibdir)'"; \
	  $(MKDIR_P) "$(DESTDIR)$(pkglibdir)" || exit 1; \
	  echo " $(LIBTOOL) $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=install $(INSTALL) $(INSTALL_STRIP_FLAG) $$list2 '$(DESTDIR)$(pkglibdir)'"; \
	  $(LIBTOOL) $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=install $(INSTALL) $(INSTALL_STRIP_FLAG) $$list2 "$(DESTDIR)$(pkglibdir)"; \
	}

uninstall-pkglibLTLIBRARIES:
	@$(NORMAL_UNINSTALL)
	@list='$(pkglib_LTLIBRARIES)'; test -n "$(pkglibdir)" || list=; \
	for p in $$list; do \
	  $(am__strip_dir) \
	  echo " $(LIBTOOL) $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=uninstall rm -f '$(DESTDIR)$(pkglibdir)/$$f'"; \
	  $(LIBTOOL) $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=uninstall rm -f "$(DESTDIR)$(pkglibdir)/$$f"; \
	done

clean-pkglibLTLIBRARIES:
	-test -z "$(pkglib_LTLIBRARIES)" || rm -f $(pkglib_LTLIBRARIES)
	@list='$(pkglib_LTLIBRARIES)'; \
	locs=`for p in $$list; do echo $$p; done | \
	      sed 's|^[^/]*$$|.|; s|/[^/]*$$||; s|$$|/so_locations|' | \
	      sort -u`; \
	test -z "$$locs" || { \
	  echo rm -f $${locs}; \
	  rm -f $${locs}; \
	}

omhttps.la: $(omhttps_la_OBJECTS) $(omhttps_la_DEPENDENCIES) $(EXTRA_omhttps_la_DEPENDENCIES) 
	$(AM_V_CCLD)$(omhttps_la_LINK) -rpath $(pkglibdir) $(omhttps_la_OBJECTS) $(omhttps_la_LIBADD) $(LIBS)

mostlyclean-compile:
	-rm -f *.$(OBJEXT)

distclean-compile:
	-rm -f *.tab.c

include ./$(DEPDIR)/omhttps_la-omhttps.Plo

.c.o:
	$(AM_V_CC)depbase=`echo $@ | sed 's|[^/]*$$|$(DEPDIR)/&|;s|\.o$$||'`;\
	$(COMPILE) -MT $@ -MD -MP -MF $$depbase.Tpo -c -o $@ $< &&\
	$(am__mv) $$depbase.Tpo $$depbase.Po
#	$(AM_V_CC)source='$<' object='$@' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(COMPILE) -c -o $@ $<

.c.obj:
	$(AM_V_CC)depbase=`echo $@ | sed 's|[^/]*$$|$(DEPDIR)/&|;s|\.obj$$||'`;\
	$(COMPILE) -MT $@ -MD -MP -MF $$depbase.Tpo -c -o $@ `$(CYGPATH_W) '$<'` &&\
	$(am__mv) $$depbase.Tpo $$depbase.Po
#	$(AM_V_CC)source='$<' object='$@' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(COMPILE) -c -o $@ `$(CYGPATH_W) '$<'`

.c.lo:
	$(AM_V_CC)depbase=`echo $@ | sed 's|[^/]*$$|$(DEPDIR)/&|;s|\.lo$$||'`;\
	$(LTCOMPILE) -MT $@ -MD -MP -MF $$depbase.Tpo -c -o $@ $< &&\
	$(am__mv) $$depbase.Tpo $$depbase.Plo
#	$(AM_V_CC)source='$<' object='$@' libtool=yes \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(LTCOMPILE) -c -o $@ $<

omhttps_la-omhttps.lo: omhttps.c
	$(AM_V_CC)$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=compile $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(omhttps_la_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -MT omhttps_la-omhttps.lo -MD -MP -MF $(DEPDIR)/omhttps_la-omhttps.Tpo -c -o omhttps_la-omhttps.lo `test -f 'omhttps.c' || echo '$(srcdir)/'`omhttps.c
	$(AM_V_at)$(am__mv) $(DEPDIR)/omhttps_la-omhttps.Tpo $(DEPDIR)/omhttps_la-omhttps.Plo
#	$(AM_V_CC)source='omhttps.c' object='omhttps_la-omhttps.lo' libtool=yes \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=compile $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(omhttps_la_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -c -o omhttps_la-omhttps.lo `test -f 'omhttps.c' || echo '$(srcdir)/'`omhttps.c

mostlyclean-libtool:
	-rm -f *.lo

clean-libtool:
	-rm -rf .libs _libs

ID: $(am__tagged_files)
	$(am__define_uniq_tagged_files); mkid -fID $$unique
tags: tags-am
TAGS: tags

tags-am: $(TAGS_DEPENDENCIES) $(am__tagged_files)
	set x; \
	here=`pwd`; \
	$(am__define_uniq_tagged_files); \
	shift; \
	if test -z "$(ETAGS_ARGS)$$*$$unique"; then :; else \
	  test -n "$$unique" || unique=$$empty_fix; \
	  if test $$# -gt 0; then \
	    $(ETAGS) $(ETAGSFLAGS) $(AM_ETAGSFLAGS) $(ETAGS_ARGS) \
	      "$$@" $$unique; \
	  else \
	    $(ETAGS) $(ETAGSFLAGS) $(AM_ETAGSFLAGS) $(ETAGS_ARGS) \
	      $$unique; \
	  fi; \
	fi
ctags: ctags-am

CTAGS: ctags
ctags-am: $(TAGS_DEPENDENCIES) $(am__tagged_files)
	$(am__define_uniq_tagged_files); \
	test -z "$(CTAGS_ARGS)$$unique" \
	  || $(CTAGS) $(CTAGSFLAGS) $(AM_CTAGSFLAGS) $(CTAGS_ARGS) \
	     $$unique

GTAGS:
	here=`$(am__cd) $(top_builddir) && pwd` \
	  && $(am__cd) $(top_srcdir) \
	  && gtags -i $(GTAGS_ARGS) "$$here"
cscopelist: cscopelist-am

cscopelist-am: $(am__tagged_files)
	list='$(am__tagged_files)'; \
	case "$(srcdir)" in \
	  [\\/]* | ?:[\\/]*) sdir="$(srcdir)" ;; \
	  *) sdir=$(subdir)/$(srcdir) ;; \
	esac; \
	for i in $$list; do \
	  if test -f "$$i"; then \
	    echo "$(subdir)/$$i"; \
	  else \
	    echo "$$sdir/$$i"; \
	  fi; \
	done >> $(top_builddir)/cscope.files

distclean-tags:
	-rm -f TAGS ID GTAGS GRTAGS GSYMS GPATH tags

distdir: $(DISTFILES)
	@srcdirstrip=`echo "$(srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	topsrcdirstrip=`echo "$(top_srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	list='$(DISTFILES)'; \
	  dist_files=`for file in $$list; do echo $$file; done | \
	  sed -e "s|^$$srcdirstrip/||;t" \
	      -e "s|^$$topsrcdirstrip/|$(top_builddir)/|;t"`; \
	case $$dist_files in \
	  */*) $(MKDIR_P) `echo "$$dist_files" | \
			   sed '/\//!d;s|^|$(distdir)/|;s,/[^/]*$$,,' | \
			   sort -u` ;; \
	esac; \
	for file in $$dist_files; do \
	  if test -f $$file || test -d $$file; then d=.; else d=$(srcdir); fi; \
	  if test -d $$d/$$file; then \
	    dir=`echo "/$$file" | sed -e 's,/[^/]*$$,,'`; \
	    if test -d "$(distdir)/$$file"; then \
	      find "$(distdir)/$$file" -type d ! -perm -700 -exec chmod u+rwx {} \;; \
	    fi; \
	    if test -d $(srcdir)/$$file && test $$d != $(srcdir); then \
	      cp -fpR $(srcdir)/$$file "$(distdir)$$dir" || exit 1; \
	      find "$(distdir)/$$file" -type d ! -perm -700 -exec chmod u+rwx {} \;; \
	    fi; \
	    cp -fpR $$d/$$file "$(distdir)$$dir" || exit 1; \
	  else \
	    test -f "$(distdir)/$$file" \
	    || cp -p $$d/$$file "$(distdir)/$$file" \
	    || exit 1; \
	  fi; \
	done
check-am: all-am
check: check-am
all-am: Makefile $(LTLIBRARIES)
installdirs:
	for dir in "$(DESTDIR)$(pkglibdir)"; do \
	  test -z "$$dir" || $(MKDIR_P) "$$dir"; \
	done
install: install-am
install-exec: install-exec-am
install-data: install-data-am
uninstall: uninstall-am

install-am: all-am
	@$(MAKE) $(AM_MAKEFLAGS) install-exec-am install-data-am

installcheck: installcheck-am
install-strip:
	if test -z '$(STRIP)'; then \
	  $(MAKE) $(AM_MAKEFLAGS) INSTALL_PROGRAM="$(INSTALL_STRIP_PROGRAM)" \
	    install_sh_PROGRAM="$(INSTALL_STRIP_PROGRAM)" INSTALL_STRIP_FLAG=-s \
	      install; \
	else \
	  $(MAKE) $(AM_MAKEFLAGS) INSTALL_PROGRAM="$(INSTALL_STRIP_PROGRAM)" \
	    install_sh_PROGRAM="$(INSTALL_STRIP_PROGRAM)" INSTALL_STRIP_FLAG=-s \
	    "INSTALL_PROGRAM_ENV=STRIPPROG='$(STRIP)'" install; \
	fi
mostlyclean-generic:

clean-generic:

distclean-generic:
	-test -z "$(CONFIG_CLEAN_FILES)" || rm -f $(CONFIG_CLEAN_FILES)
	-test . = "$(srcdir)" || test -z "$(CONFIG_CLEAN_VPATH_FILES)" || rm -f $(CONFIG_CLEAN_VPATH_FILES)

maintainer-clean-generic:
	@echo "This command is intended for maintainers to use"
	@echo "it deletes files that may require special tools to rebuild."
clean: clean-am

clean-am: clean-generic clean-libtool clean-pkglibLTLIBRARIES \
	mostlyclean-am

distclean: distclean-am
	-rm -rf ./$(DEPDIR)
	-rm -f Makefile
distclean-am: clean-am distclean-compile distclean-generic \
	distclean-tags

dvi: dvi-am

dvi-am:

html: html-am

html-am:

info: info-am

info-am:

install-data-am:

install-dvi: install-dvi-am

install-dvi-am:

install-exec-am: install-pkglibLTLIBRARIES

install-html: install-html-am

install-html-am:

install-info: install-info-am

install-info-am:

install-man:

install-pdf: install-pdf-am

install-pdf-am:

install-ps: install-ps-am

install-ps-am:

installcheck-am:

maintainer-clean: maintainer-clean-am
	-rm -rf ./$(DEPDIR)
	-rm -f Makefile
maintainer-clean-am: distclean-am maintainer-clean-generic

mostlyclean: mostlyclean-am

mostlyclean-am: mostlyclean-compile mostlyclean-generic \
	mostlyclean-libtool

pdf: pdf-am

pdf-am:

ps: ps-am

ps-am:

uninstall-am: uninstall-pkglibLTLIBRARIES

.MAKE: install-am install-strip

.PHONY: CTAGS GTAGS TAGS all all-am check check-am clean clean-generic \
	clean-libtool clean-pkglibLTLIBRARIES cscopelist-am ctags \
	ctags-am distclean distclean-compile distclean-generic \
	distclean-libtool distclean-tags distdir dvi dvi-am html \
	html-am info info-am install install-am install-data \
	install-data-am install-dvi install-dvi-am install-exec \
	install-exec-am install-html install-html-am install-info \
	install-info-am install-man install-pdf install-pdf-am \
	install-pkglibLTLIBRARIES install-ps install-ps-am \
	install-strip installcheck installcheck-am installdirs \
	maintainer-clean maintainer-clean-generic mostlyclean \
	mostlyclean-compile mostlyclean-generic mostlyclean-libtool \
	pdf pdf-am ps ps-am tags tags-am uninstall uninstall-am \
	uninstall-pkglibLTLIBRARIES


# Tell versions [3.59,3.63) of GNU make to not export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT: