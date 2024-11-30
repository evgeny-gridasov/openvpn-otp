#! /bin/bash

[[ -z "$TRAVIS_BUILD_NUMBER" ]] && ITERATION='1' || ITERATION="$TRAVIS_BUILD_NUMBER"

apt-get install -y ruby ruby-dev rubygems build-essential
gem install --no-ri --no-rdoc fpm

mkdir -p /tmp/openvpn-otp-build/usr/lib/openvpn
cp /usr/lib/openvpn/openvpn-otp.* /tmp/openvpn-otp-build/usr/lib/openvpn

fpm -s dir -C /tmp/openvpn-otp-build -t deb --name openvpn-otp-snowrider311 \
  --version $PACKAGE_VERSION --iteration $ITERATION --depends openvpn
