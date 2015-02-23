OpenVPN OTP Authentication support
==================================

This plug-in adds support for OTP time based tokens for OpenVPN.
Compatible with Google Authenticator software token, other software and hardware based OTP time tokens.

Compile and install openvpn-otp.so file to your OpenVPN plugins directory (usually /usr/lib/openvpn or /usr/lib64/openvpn/plugins).

To bootstrap autotools (generate configure and Makefiles):

    ./autogen.sh

Build and install with:

    ./configure --prefix=/usr
    make install

The default install location (PREFIX/LIB/openvpn) can be changed by
passing the directory with --with-openvpn-plugin-dir to ./configure:

    ./configure --with-openvpn-plugin-dir=/plugin/dir

Add the following lines to your server config:

    # use otp passwords
    plugin /usr/lib64/openvpn/plugins/openvpn-otp.so

Add the following lines to your clients' configs:

    # use username/password authentication
    auth-user-pass
    # do not cache auth info
    auth-nocache

OpenVPN will re-negotiate username/password details every 3600 seconds by default. To disable that behaviour add the following line
to both client and server configs:

    # disable username/password renegotiation
    reneg-sec 0

At this moment the plugin does not support any configuration. You will have to recompile it if you want any changes to the otp parameters. There is a special case for 60 second hardware time tokens, see configuration below.
The secret file should be placed at /etc/ppp/otp-secrets and set file permissions to 0600. Default OTP parameters are:
    
    Maximum allowed clock slop = 180
    T0 value for TOTP (time drift) = 0
    Step value for TOTP = 30
    Number of digits to use from TOTP hash = 6
    Step value for MOTP = 10 

The otp-secrets file format is exactly the same as for ppp-otp plugin which makes it very convenient to have PPP and OpenVPN running on the same machine and using the same secrets file. The secrets file has the following layout:

    # user server type:hash:encoding:key:pin:udid client
    # where type is totp, totp-60-6 or motp
    #       hash should be sha1 in most cases
    #       encoding is base32, hex or text
    #       key is your key in encoding format
    #       pin is a 4-6 digit pin
    #       udid is used in motp mode
    #
    # use sha1/base32 for Google Authenticator
    bob otp totp:sha1:base32:K7BYLIU5D2V33X6S:1234:xxx *
    
    # use totp-60-6 and sha1/hex for hardware based 60 seconds / 6 digits tokens
    mike otp totp-60-6:sha1:hex:5c5a75a87ba1b48cb0b6adfd3b7a5a0e:6543:xxx *
    
    # use text encoding for clients supporting plain text keys
    jane otp totp:sha1:text:1234567890:9876:xxx *
    
When users vpn in, they will need to provide their username and pin+current OTP number from the OTP token. Example for user bob:

    username: bob
    password: 1234920151


Troubleshooting
===============

Make sure that time is in sync on the server and on your phone/tablet/other OTP client device.
You may use oathtool for token verification or as an OTP client:

    $ oathtool -b K7BYLIU5D2V33X6S
    995277

The tokens should be identical on your OTP client and OpenVPN server.

Also, check that /etc/ppp/otp-secrets file:
 - is accessible by OpenVPN
 - has spaces as field separators
 - has UNIX style line separator (new line only without CR)


Inspired by ppp-otp plugin written by GitHub user kolbyjack
This plugin written by Evgeny Gridasov (evgeny.gridasov@gmail.com)

