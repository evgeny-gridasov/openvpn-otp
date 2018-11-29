AC_PREREQ([2.68])
AC_INIT([openvpn-otp], 20140112)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src])
AC_CONFIG_HEADERS([config.h])

LT_INIT([disable-static])
AC_CONFIG_MACRO_DIR([m4])

case "$host" in
*-*-freebsd*)
	CPPFLAGS="$CPPFLAGS -I/usr/local/include"
	LDFLAGS="$LDFLAGS -L/usr/local/lib -Wl,-rpath,/usr/local/lib"
	pkgconfigdir="/usr/lib/pkgconfig"
	;;
*-*-openbsd*)
	CPPFLAGS="$CPPFLAGS -I/usr/local/include"
	LDFLAGS="$LDFLAGS -L/usr/local/lib -Wl,-rpath,/usr/local/lib"
	pkgconfigdir="/usr/lib/pkgconfig"
	;;
esac

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX

# Checks for libraries.
AC_CHECK_LIB([crypto], [HMAC_CTX_init, EVP_MD_CTX_create], [],
	[AC_CHECK_LIB([crypto], [HMAC_CTX_new, EVP_MD_CTX_new], [AC_DEFINE([HAVE_OPENSSL_110], [1], [Using OpenSSL 1.1.0])], [AC_MSG_ERROR([OpenSSL libraries required])]) ])

# Checks for header files.
AC_CHECK_HEADERS([endian.h], [],
	[AC_CHECK_HEADERS([sys/endian.h], [], [AC_MSG_ERROR([Missing endian header])] ) ])
AC_CHECK_HEADERS([inttypes.h netinet/in.h stdint.h string.h], [],
	[AC_MSG_ERROR([Missing system headers])]   )
AC_CHECK_HEADERS([openssl/evp.h openssl/hmac.h], [],
	[AC_MSG_ERROR([OpenSSL headers missing])])
AC_CHECK_HEADERS([openvpn/openvpn-plugin.h], [],
	[AC_CHECK_HEADERS( [openvpn-plugin.h], [], [AC_MSG_ERROR([OpenVPN headers missing])] ) ])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([memset strcasecmp strchr strncasecmp])

# Plugin dir
AC_ARG_WITH(openvpn-plugin-dir,
    [AS_HELP_STRING([--with-openvpn-plugin-dir=<dir>],[OpenVPN plugin directory])])
if ! test -z "$with_openvpn_plugin_dir"; then
    OPENVPN_PLUGIN_DIR="$with_openvpn_plugin_dir"
else
    OPENVPN_PLUGIN_DIR="${libdir}/openvpn"
fi
AC_SUBST(OPENVPN_PLUGIN_DIR)

AC_OUTPUT(Makefile src/Makefile)
