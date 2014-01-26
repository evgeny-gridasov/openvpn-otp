OpenVPN OTP Authentication support
==================================

This plug-in adds support for OTP time based tokens for OpenVPN.
Compatible with Google Authenticator software token or software/hardware based OTP tokens.

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

At this moment the plugin does not support any configuration. You will have to recompile it if you want any changes to otp parameters.
The secret file should be placed at /etc/ppp/otp-secrets. Default OTP parameters are:
    
    Maximum allowed clock slop = 180
    T0 value for TOTP (time drift) = 0
    Step value for TOTP = 30
    Number of digits to use from TOTP hash = 6
    Step value for MOTP = 10 

The otp-secrets file format is exactly the same as for ppp-otp plugin which makes it very convenient to have PPP and OpenVPN running on
the same machine and using the same secrets file. The secrets file has the following layout:

    # user server type:hash:encoding:key:pin:udid client
    # where type is topt or mopt
    #       hash should be sha1 in most cases
    #       encoding is base32 or text
    #       key is your key in encoding format
    #       pin is a 4 digit pin
    #       udid is used in motp mode
    #
    # use sha1/base32 for Google Authenticator
    bob otp topt:sha1:base32:K7BYLIU5D2V33X6S:1234:xxx *
    
    # use text encoding for text based format
    jane otp topt:sha1:text:1234567890:9876:xxx *
    
When users vpn in, they will need to provide their username and pin+current OTP number from the OTP token. Example for user bob:

    username: bob
    password: 1234920151

Inspired by ppp-otp plugin written by GitHub user kolbyjack
This plugin written by Evgeny Gridasov (evgeny.gridasov@gmail.com)

