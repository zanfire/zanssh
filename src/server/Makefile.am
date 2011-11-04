INCLUDES = \
	-I$(top_srcdir)/src/base \
	-I$(top_srcdir)/src/ssh

bindir = $(top_srcdir)/out/
bin_PROGRAMS = zansshserver
zansshserver_LDADD =  \
	$(top_srcdir)/src/ssh/libzanssh.a \
	$(top_srcdir)/src/base/libzanbase.a $(AM_LDFLAGS)

zansshserver_SOURCES = main.cpp \
	SSHServer.cpp
