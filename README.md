# Jomon
![Screenshot](https://user-images.githubusercontent.com/18684676/211202984-10aebda2-be93-4c91-9e7c-8967045866d9.png)

Jomon is a network forensics and passive sniffer tool. It monitors all incoming/outgoing network
traffic, without the use of libpcap, and the processes that are generating this
traffic.

It supports packet filtering by writing BPF assembly directly or writing in a
higher level tcpdump syntax (tcpdump syntax has very limited support for now).

It uses a minimal set of libraries, libncurses for the UI and libGeoIP
for geolocation (optional). The BPF scanner/lexical analyzer is made with the
help of re2c.

### BPF
To for example catch all IPv4 packets with options, you can write
```
ip[0] & 0xf != 5
```

This works both as a display filter (use **e** or **F9** in the ncurses ui) and
capture filter (with the **-f** option on the command line). The equivalent
assembly
```
    ldh    [12]
    jeq    #0x800, L1, L3
L1: ldb    [14]
    and    #0xf
    jeq    #0x5, L3, L2
L2: ret    #-1
L3: ret    #0
```

can only be specified as a capture filter and read from file with the **-F**
option on the command line.

### Build and installation

```
$ ./configure
$ make
$ make install
```

In order to use the GeoIP databases from MaxMind you need to download them yourself.
On Arch Linux the free databases are in the geoip-database and geoip-database-extra
packages.

To disable libGeoIP
```
$ ./configure --disable-geoip
```

Display help
```
$ ./configure --help
```

#### Arch Linux
To install on Arch Linux
```
$ pacman -S jomon
```

#### FreeBSD
Need to have bash and gmake to build on FreeBSD

### Code style
This project uses K&R style

### Screenshots

Main screen decoded view
![main-screen-dec](https://user-images.githubusercontent.com/18684676/152642647-b967af27-3b30-4d54-a021-4d7e3e2d23a9.png)

Main screen hexmode view
![main-screen-hex2](https://user-images.githubusercontent.com/18684676/152642732-acb59100-6865-45ee-8986-83e8a45216fe.png)

Connection list
![connection-list](https://user-images.githubusercontent.com/18684676/152642829-164d6b39-d3f0-42b6-a03f-117822a4ce0a.png)

Process view
![process2](https://user-images.githubusercontent.com/18684676/152642459-33a8852c-9af3-4696-a085-4d22d50ac967.png)

Follow stream ascii mode
![ascii-mode](https://user-images.githubusercontent.com/18684676/152643215-6c065711-38a5-44a2-a254-c45235618226.png)
