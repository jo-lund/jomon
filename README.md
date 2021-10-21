# Monitor

Monitor is a network forensics tool. It monitors all incoming/outgoing network
traffic without the use of libpcap, and the processes that are generating this
traffic.

It supports packet filtering by writing BPF assembly directly or writing in a
higher level tcpdump syntax (tcpdump syntax has very limited support for now,
and the compiler needs to be refactored to handle this better).

It uses a minimal set of libraries, libncurses for the UI and libGeoIP
for geolocation (optional). The BPF scanner/lexical analyzer is made with the
help of re2c.

### Build

```
$ ./configure
$ make
$ make install
```

#### FreeBSD
Need to have bash and gmake to build on FreeBSD

### Code style
This project uses K&R style

### Screenshots

Main screen decoded view
![main-screen-dec](https://user-images.githubusercontent.com/18684676/132952126-b16ac592-3293-494c-889c-9ac49ae1b373.png)

Main screen hexmode view
![main-screen-hex2](https://user-images.githubusercontent.com/18684676/132952554-a8348055-957b-4be4-bbdf-2053c3318101.png)

Connection list
![connection-list](https://user-images.githubusercontent.com/18684676/132952633-dc9f40f5-d6d3-45c0-bcf9-900b1c924b0d.png)

Follow stream ascii mode
![ascii-mode](https://user-images.githubusercontent.com/18684676/132952652-81d3bee3-024f-4091-b855-ef09ae9b92df.png)
