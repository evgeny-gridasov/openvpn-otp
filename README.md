OpenVPN OTP Authentication support
==================================

This plug-in adds support for time based OTP (totp) and HMAC based OTP (hotp) tokens for OpenVPN.
Compatible with Google Authenticator software token, other software and hardware based OTP tokens.

Compile and install ``openvpn-otp.so`` file to your OpenVPN plugins directory (usually ``/usr/lib/openvpn`` or ``/usr/lib64/openvpn/plugins``).

Be sure you've installed the following packages first:
* `autoconf`
* `libtool`
* `libssl-dev`/`openssl-devel`

To bootstrap autotools (generate configure and Makefiles):

    ./autogen.sh

Build and install with:

    ./configure --prefix=/usr
    make install

The default install location (PREFIX/LIB/openvpn) can be changed by
passing the directory with ``--with-openvpn-plugin-dir`` to ``./configure``:

    ./configure --with-openvpn-plugin-dir=/plugin/dir

Add the following lines to your OpenVPN server configuration file to deploy OTP plugin with default settings. For OpenVPN <=2.3.x, use:

    # use otp passwords with default settings (OpenVPN<=2.3.x syntax)
    plugin /usr/lib64/openvpn/plugins/openvpn-otp.so

For OpenVPN 2.4, use double quotes:

    # use otp passwords with default settings (OpenVPN>=2.4 syntax)
    plugin "/usr/lib64/openvpn/plugins/openvpn-otp.so"

By default the following settings are applied:

    otp_secrets=/etc/ppp/otp-secrets      # OTP secret file
    otp_slop=180                          # Maximum allowed clock slop (seconds)
    totp_t0=0                             # T0 value for TOTP (time drift in seconds)
    totp_step=30                          # Step value for TOTP (seconds), should be 30 seconds for soft tokens and 60 seconds for hardware tokens
    totp_digits=6                         # Number of digits to use from TOTP hash
    motp_step=10                          # Step value for MOTP
    hotp_syncwindow=2                     # Maximum drifts allowed for clients to resynchronise their tokens' counters (see rfc4226#section-7.4)
    hotp_counters=/var/spool/openvpn/hotp-counters/      # HOTP counters directory
    debug=0                               # Debug mode: 0=disabled, 1=enabled

Add these variables on the same line as ``plugin /.../openvpn-otp.so`` line if you want different values.
If you skip one of the variables, the default value will be applied. For OpenvVPN <=2.3.x, the configuration item should look like this:

    # use otp passwords with custom settings (OpenVPN<=2.3.x syntax)
    plugin /usr/lib64/openvpn/plugins/openvpn-otp.so otp_secrets=/etc/my_otp_secret_file otp_slop=300 totp_t0=2 totp_step=30 totp_digits=8 motp_step=10

OpenVPN 2.4 requires plugin parameters to be put in double quotes:

    # use otp passwords with custom settings (OpenVPN>=2.4 syntax)
    plugin "/usr/lib64/openvpn/plugins/openvpn-otp.so" "otp_secrets=/etc/my_otp_secret_file otp_slop=300 totp_t0=2 totp_step=30 totp_digits=8 motp_step=10"


It is important to mention that totp_step has to be same on both, the client and server, because it is used for calculation of current token value.

Add the following lines to your OpenVPN clients' configuration files:

    # use username/password authentication
    auth-user-pass
    # do not cache auth info
    auth-nocache

OpenVPN will re-negotiate username/password details every 3600 seconds by default. To disable that behaviour, add the following line to both client and server configs:

    # disable username/password renegotiation
    reneg-sec 0

The ``otp-secrets`` file format is exactly the same as for ppp-otp plugin, which makes it very convenient to have PPP and OpenVPN running on the same machine and using the same secrets file. The secrets file has the following layout:

    # user server type:hash:encoding:key:pin:udid client
    # where type is totp, totp-60-6 or motp
    #       hash should be sha1 in most cases
    #       encoding is base32, hex or text
    #       key is your key in encoding format
    #       pin may be a number or a string (may be empty)
    #       udid is used only in motp mode and ignored in totp mode
    #
    # use sha1/base32 for Google Authenticator with a simple pin
    bob otp totp:sha1:base32:K7BYLIU5D2V33X6S:1234:xxx *
    
    # use sha1/base32 for Google Authenticator with a strong pin
    alice otp totp:sha1:base32:46HV5FIYE33TKWYP:5uP3rH4x0r:xxx *
    
    # use sha1/base32 for Google Authenticator without a pin
    john otp totp:sha1:base32:LJYHR64TUI7IL3RD::xxx *

    # use sha1/base32 for HOTP without a pin
    lucie otp hotp:sha1:base32::MT4GWEZTSRBV2QQC:xxx *

    # use totp-60-6 and sha1/hex for hardware based 60 seconds / 6 digits tokens
    mike otp totp-60-6:sha1:hex:5c5a75a87ba1b48cb0b6adfd3b7a5a0e:6543:xxx *
    
    # use text encoding for clients supporting plain text keys
    jane otp totp:sha1:text:1234567890:9876:xxx *

    # allow multiple tokens without a pin for a specific user
    hobbes otp totp:sha1:base32:LJYHR64TUI7IL3RD::xxx *
    hobbes otp totp:sha1:base32:7VXNJAFPYYKO3ILO::xxx *
    
When users vpn in, they will need to provide their username and pin+current OTP number from the OTP token. Examples for users bob, alice and john:

```
username: bob
password: 1234920151

username: alice
password: 5uP3rH4x0r797104

username: john
password: 408923
```



HOTP counters initialisation
============================

HOTP counters are stored in files, which reside under the ``hotp-counters`` directory (``/var/spool/openvpn/hotp-counters/`` by
default). OpenVPN server process should have enough permissions to read and modify files in that directory.

For each HOTP entry in the ``otp-secrets`` files, we compute the SHA1
checksum of the secret key, and use the resulting lower case string as the filename.

For example, the following HOTP entry
```
lucie otp hotp:sha1:base32::MT4GWEZTSRBV2QQC:xxx *
```
has SHA1(MT4GWEZTSRBV2QQC) = a0b2e3795f7ca9e60183af274a004cdd0ac9276f and the HOTP counter file 
should be read and stored in ``/var/spool/openvpn/hotp-counters/a0b2e3795f7ca9e60183af274a004cdd0ac9276f``.

The administrator has to create and populate each HOTP counter file with initial value after adding new HOTP records to ``otp-secrets`` file.
The following command will do the job:

        echo -n 0 > /var/spool/openvpn/hotp-counters/"$(echo -n 'secretkey' | sha1sum | cut -c-40)"


SELinux
===============
The following exceptions are required for this plugin to work properly on a system with Security Enhanced Linux running in enforcing mode:

```
#============= openvpn_t ==============

allow openvpn_t auth_home_t:file { unlink open };
allow openvpn_t user_home_dir_t:dir { write remove_name add_name };
allow openvpn_t user_home_dir_t:file { rename write getattr read create unlink open };
allow openvpn_t pppd_etc_t:dir search;
allow openvpn_t pppd_etc_t:file { read getattr open };
```

Alternative SELinux policy reported to work with CentOS:
```
$ yum install policycoreutils-python \
    selinux-policy-devel
$ cat - <<EOF > openvpn_otp.te
module openvpn_otp 1.0;

require {
        type openvpn_t;
        type pppd_etc_t;
        class dir { search getattr open };
        class file { ioctl lock read getattr open };
}

#============= openvpn_t ==============
read_files_pattern(openvpn_t, pppd_etc_t, pppd_etc_t)
EOF
$ make -f /usr/share/selinux/devel/Makefile openvpn_otp.pp
$ semodule --install openvpn_otp.pp 
```

Troubleshooting
===============

Make sure that time is in sync on the server and on your phone/tablet/other OTP client device.
You may use ``oathtool`` for token verification on your OpenVPN server:

    # for TOTP, type: 
    $ oathtool --totp -b K7BYLIU5D2V33X6S
    995277
    
    # for HOTP, type:
    $ oathtool -b -c 5 NFIJ5GSNU574OU6B
    214648

The tokens should be identical on your OTP client and OpenVPN server.
You may also enable debug mode to log user-provided and expected credentials (do not use in production environments):

    # use otp passwords with custom settings
    plugin /usr/lib64/openvpn/plugins/openvpn-otp.so debug=1 [...other settings...]

Also check that ``/etc/ppp/otp-secrets file``:
 - is accessible by OpenVPN
 - has spaces as field separators
 - has UNIX style line separator (new line only without CR)

Make sure that OpenVPN server process can read and modify files in ``/var/spool/openvpn/hotp-counters/`` directory.


Inspired by ppp-otp plugin written by GitHub user kolbyjack. This plugin written by Evgeny Gridasov (evgeny.gridasov@gmail.com)

