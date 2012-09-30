---
emtraceroute
---

- This traceroute is based on eventmachine.

## This is how it works

    $ sudo traceroute 'google.co.jp'
    1. 0.004s :: 192.168.X.XXX :: Reserved
    2. 0.008s :: 118.23.XX.XXX :: Japan
    3. 0.007s :: 118.23.XX.XXX :: Japan
    4. 0.009s :: 221.184.X.XXX :: Japan, Niigata, Niigata
    5. 0.008s :: 60.37.XX.XX :: Japan
    6. 0.009s :: 60.37.XX.XXX :: Japan
    7. 0.008s :: 60.37.XX.XXX :: Japan
    8. 0.01s :: 118.23.XX.XXX :: Japan
    9. 0.04s :: 211.129.XX.XX :: Japan
    10. 0.01s :: 209.85.XXX.XX :: United States, California, Mountain View
    11. 0.01s :: 209.85.XXX.XXX :: United States, California, Mountain View
    12. 0.011s :: 173.194.XX.XX :: United States, California, Mountain View

## How to install

first, clone from github

    git clone https://github.com/kubo39/emtraceroute.git

second, build gemspec

    gem build emtraceroute.gemspec

third, gem install

    sudo gem install emtraceroute --local

## options

-t, --timeout: hop timeout seconds.

-r, --tries: retry counts.

-m, --max_hops: max size of traceroute hops.

-s, --silent: only show results at the end.

-g, --no-geoip: not display geoip location.