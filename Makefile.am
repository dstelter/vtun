AUTOMAKE_OPTIONS = subdir-objects
logdir    = ${localstatedir}/log
lockdir   = ${localstatedir}/lock
piddir    = ${localstatedir}/run
INCLUDES = -DVTUN_STAT_DIR=\"${logdir}/vtun\" -DVTUN_LOCK_DIR=\"${lockdir}\" 
INCLUDES += -DVTUN_CONFIG_FILE=\"${sysconfdir}/vtun/vtund.conf\"
INCLUDES += -DVTUN_PID_FILE=\"${piddir}/vtund.pid\"
CFLAGS   = -O2 -g -Wall
YFLAGS   = -d

bin_PROGRAMS = vtund


vtund_SOURCES = auth.c client.c lfd_encrypt.c lfd_lzo.c lfd_shaper.c \
	lfd_zlib.c lib.c linkfd.c llist.c lock.c main.c netlib.c server.c \
	tunnel.c cfg_file.y cfg_parse.l

vtund_SOURCES += auth.h cfg_kwords.h compat.h driver.h lib.h linkfd.h\
	llist.h lock.h netlib.h vtun.h vtun_dh.h vtun_socks.h

EXTRA_vtund_SOURCES = linux/tun_dev.c linux/tap_dev.c freebsd/tun_dev.c openbsd/tun_dev.c\
	svr4/tun_dev.c svr4/tap_dev.c generic/tun_dev.c generic/tap_dev.c generic/pipe_dev.c\
	generic/pty_dev.c generic/tcp_proto.c generic/udp_proto.c
vtund_LDFLAGS = -export-dynamic
vtund_DEPENDENCIES =  $(HOST_SRCS:.c=.o)
vtund_LDADD = $(HOST_SRCS:.c=.o)

man_MANS = vtund.8 vtund.conf.5

EXTRA_DIST = $(man_MANS) 

CLEANFILES = cfg_file.c cfg_parse.c cfg_file.h
DISTCLEANFILES = hosttype