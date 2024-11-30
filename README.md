Travis build status: [![Build Status](https://travis-ci.org/snowrider311/openvpn-otp.svg?branch=master)](https://travis-ci.org/snowrider311/openvpn-otp)

The latest Ubuntu 16.04 Debian package (built by Travis) can be found [here](https://github.com/snowrider311/openvpn-otp/releases/latest).


OpenVPN OTP Authentication support
==================================

This plug-in adds support for time based OTP (totp) and HMAC based OTP (hotp) tokens for OpenVPN.
Compatible with Google Authenticator software token, other software and hardware based OTP tokens.


### Building

Compile and install ``openvpn-otp.so`` file to your OpenVPN plugins directory (usually ``/usr/lib/openvpn`` or ``/usr/lib64/openvpn/plugins``).

Be sure you've installed the following packages first:
* `openvpn`
* `openvpn-devel` (Some distros have `openvpn-plugin.h` file in a separate package)
* `autoconf`
* `automake`
* `libtool`
* `libssl-dev`/`openssl-devel`/`libressl-devel`

To bootstrap autotools (generate configure and Makefiles):

    ./autogen.sh

Build and install with:

    ./configure --prefix=/usr
    make install

The default install location (PREFIX/LIB/openvpn) can be changed by
passing the directory with ``--with-openvpn-plugin-dir`` to ``./configure``:

    ./configure --with-openvpn-plugin-dir=/plugin/dir


#### Building On Ubuntu 16.04 ####

The following steps were tested on a clean Ubuntu 16.04 LTS Amazon EC2 m5.large instance in January 2018 (source AMI: ubuntu/images/hvm-ssd/ubuntu-xenial-16.04-amd64-server-20180109 - ami-41e0b93b). These steps are also executed by Travis in a Docker container for every new commit made to this repository. The latest Ubuntu 16.04 Debian package (built by Travis) can be found [here](https://github.com/snowrider311/openvpn-otp/releases/latest).

If you wish to repeat this process, follow these steps on your own machine:

```
git clone https://github.com/snowrider311/openvpn-otp
cd openvpn-otp/
./ubuntu_16.04_lts_build.sh
```

The `ubuntu_16.04_lts_build.sh` script will install all needed build dependencies, perform the build, and install the libraries to `/usr/lib/openvpn`.

If you then wish to create a Debian package, you can then run this script:

```
./ubuntu_16.04_lts_package.sh
```

That script will install [FPM](https://github.com/jordansissel/fpm) and then use it to build a Debian package. If you then run `sudo dpkg -i openvpn-otp-snowrider311_*_amd64.deb` (substitute the proper version number for the asterisk), then the libraries will be installed to `/usr/lib/openvpn`. 

Note: Superuser privileges are required to run these scripts.


### Configuration

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
    password_is_cr=0                      # If set to 1, openvtp-otp will expect password as result of a challenge/response protocol  
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

OpenVPN will re-negotiate username/password details every 3600 seconds by default.
To disable that behaviour, add the following line to both client and server configs:

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
Using OpenVPN OTP for Multi-Factor Authentication
=================================================
You can use this plugin to do multi-factor authentication, by using the OpenVPN Challenge/Response feature.
For the moment this is supported by two plugins: **OpenVPN OTP** and [OpenVPN Auth-LDAP](https://github.com/threerings/openvpn-auth-ldap).

There are three side to this OpenVPN, the users and the plugins.
### OpenVPN
  The feature needs to be activated in the **client configuration file** with the ``static-challenge`` flag:

    # use Google Authenticator OTP
    static-challenge "Enter Google Authenticator Token" 1

   From the [OpenVPN manual](https://community.openvpn.net/openvpn/wiki/Openvpn24ManPage):
   ``static-challenge t e`` : Enable static challenge/response protocol using challenge text t, with echo flag given by e (0|1).
   The echo flag indicates whether or not the user's response to the challenge should be echoed.<br>
   Also, you need to add both plugins to your openvpn server configuration. Having the two auth plugins present, will require that both    of them authenticate the user, ie it is not **one of the two**, it's **both**.
   ````
   #PLUGIN SECTION
   #LDAP (Active Directory Authentication) PLUGIN
   plugin /usr/lib/openvpn/openvpn-auth-ldap.so /etc/openvpn/auth/auth-ldap.conf
   #OTP PLUGIN
   plugin /usr/local/lib/openvpn/openvpn-otp.so "password_is_cr=1 otp_secrets=/etc/openvpn/auth/otp-secrets"
   ````

### Users
If the ``static-challenge`` flag is set when the users vpn in, they will be asked for a username, a password **and a pin+current OTP number from the OTP token**. The prompt for the pin+current OTP number will be the first argument of the ``static-challenge`` option (the second argument controls if the input is masked or clear-type when the user enters it). The input for both fields is combined and passed to both plug-ins as a specially formatted password.

### Plug-ins
If the ``static-challenge`` flag is set, passwords that are passed to plugins, will have a special format. So plug-ins need to be signalled about this in their configuration:
* In **openvpn-otp** this is controlled by the ``password_is_cr`` flag and disabled by default. So to enable it, set ``password_is_cr=1`` in your openvpn-otp configuration.
* In **openvpn-auth-ldap** this is controlled by the ``PasswordIsCR`` flag in the [configuration file](https://github.com/threerings/openvpn-auth-ldap/wiki/Configuration):
````
# Uncomment and set to true to support OpenVPN Challenge/Response
# PasswordIsCR	true
````   
The various settings will pass username, password and the response to the challenge to both plug-ins. The plug-ins will parse this response (triggered by the flags in their configuration) and each plugin will authenticate the user by looking at the field that's relevant. Examples for users bob, alice and john:

```
username: bob
password: password1         # this is the LDAP password, verified by openvpn-auth-ldap
response: 1234920151        # this is a (simple) pin plus a Google OTP, verified by openvpn-otp

username: alice
password: password2         # this is the LDAP password, verified by openvpn-auth-ldap
response: 5uP3rH4x0r797104  # this is a (strong) pin plus a Google OTP, verified by openvpn-otp

username: john
password: password3         # this is the LDAP password, verified by openvpn-auth-ldap
response: 408923            # this is the Google OTP, verified by openvpn-otp
```
The last example (user john) is probably the most typical use case: a first level of authentication of username and password against the LDAP and then a second level of authenitcation using an OTP, which doesn't require a pin, because the LDAP authentication already uses a password.<br>

**Please note:** the various flags go together, i.e. making the changes only in the openvpn-otp or openvpn-auth-ldap config and not in the client config or vice versa will break the system. Also, please make sure that you're using at least version 2.0.4 of the [Auth-LDAP plugin](https://github.com/threerings/openvpn-auth-ldap).

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

Using Google Authenticator on your server and mobile
====================================================

- install `google-authenticator` on your server
- run `google-authenticator --time-based --disallow-reuse --force --rate-limit=3 --rate-time=30 --window-size=17 --issuer=foocorp --label=user@hostname --secret=/root/.user.google_authenticator > /root/user.auth`
- `user.auth` file will contain the key for entry into `opt-secrets`, and the Google URL containing the image to be scanned with the Google Authenticator mobile app


Supported Operating Systems
===========================

This plugin has been successfully compiled and tested with:

 - Ubuntu Linux 14.04 / 16.04 / 18.04
 - CentOS / RHEL 7
 - FreeBSD 11.2
 - [Archlinux](//aur.archlinux.org/packages/openvpn-otp)
 - OpenBSD 6.4
 - NetBSD 8.0
 - DragonFly BSD 5.4

In OpenBSD, please use autoconf 2.69 and automake 1.15.1. You might have to export version numbers before running `./autogen.sh`:
```
export AUTOMAKE_VERSION=1.15
export AUTOCONF_VERSION=2.69
```
It should work in other *NIX environments, please raise an issue if it does not.

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
