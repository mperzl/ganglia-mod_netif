AM_CFLAGS  = -I$(top_builddir)/include -I$(top_builddir)/lib -I$(top_builddir)/libmetrics

if STATIC_BUILD
noinst_LTLIBRARIES    = libmodnetif.la
libmodnetif_la_SOURCES = mod_netif.c 
else
pkglib_LTLIBRARIES    = modnetif.la
modnetif_la_SOURCES = mod_netif.c 
modnetif_la_LDFLAGS = -module -avoid-version
modnetif_la_LIBADD = $(top_builddir)/libmetrics/libmetrics.la

EXTRA_DIST = ../conf.d/netif.conf
endif

INCLUDES = @APR_INCLUDES@

