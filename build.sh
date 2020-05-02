#!/bin/bash

check_pkgconf()
{
    echo -n "[*] Checking for pkgconf... "

    command -v pkgconf >/dev/null ||
        {
            echo "FAIL";
            echo;
            echo -n "pkgconf needs to be installed. This can be installed with ";
            echo "\"pacman -S pkgconf\" or equivalent command for your distribution.";
            exit 1;
        }

    echo "OK"
}

check_ncurses()
{
    echo -n "[*] Checking for libncurses... "

    if ! $(pkgconf --exists ncurses); then
        echo "FAIL"
        echo
        echo -n "You need a functioning install of libncurses. "
        echo -n "This can be installed with \"pacman -S ncurses\" or equivalent "
        echo "command for your distribution."
        exit 1
    fi

    echo "OK"
}

check_geoip()
{
    echo -n "[*] Checking for libGeoIP... "

    # TODO: Define a build without libGeoIP
    if ! $(pkgconf --exists geoip); then
        echo "FAIL"
        echo
        echo -n "You need a functioning install of libGeoIP. "
        echo -n "This can be installed with \"pacman -S geoip geoip-database "
        echo "geoip-database-extra\" or equivalent command for your distribution."
        exit 1
    fi

    echo "OK"
}

check_pkgconf
check_ncurses
check_geoip
