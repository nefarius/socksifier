# Socksifier

A Windows DLL which hooks the `connect()` API to redirect sockets to a SOCKS5 proxy server.

[![Build status](https://ci.appveyor.com/api/projects/status/bwesvx70s524t30w/branch/master?svg=true)](https://ci.appveyor.com/project/nefarius/socksifier/branch/master)

## Build

[Follow the Vcpkg Quick Start](https://github.com/Microsoft/vcpkg#quick-start) and install the following packages:

- `.\vcpkg install spdlog:x86-windows-static spdlog:x64-windows-static detours:x86-windows-static detours:x64-windows-static`

## Getting started

To enable the redirection you just have to inject the DLL into your target process.

Set up the following environment variables to configure the DLL. Default values are used if omitted.

- `SOCKSIFIER_ADDRESS` - IP address of the SOCKS5 proxy to connect to (defaults to `127.0.0.1`)
- `SOCKSIFIER_PORT` - Port of the SOCKS5 proxy to connect to (defaults to `1080`)
- `SOCKSIFIER_LOGFILE` - Absolute path or file name to write the log to (useful for diagnostics)

## Sources

- [Windows Sockets Error Codes](https://docs.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2)
- [WSAEWOULDBLOCK error on non-blocking Connect()](https://stackoverflow.com/questions/14016579/wsaewouldblock-error-on-non-blocking-connect)
- [ConnectEx function](https://docs.microsoft.com/en-gb/windows/win32/api/mswsock/nc-mswsock-lpfn_connectex)
- [connect function](https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-connect)
- [WSAGetOverlappedResult function](https://docs.microsoft.com/en-gb/windows/win32/api/winsock2/nf-winsock2-wsagetoverlappedresult)
- [Working ConnectEx example](https://gist.github.com/joeyadams/4158972)
- [Simple SOCKS5 client written in C++](https://github.com/rudolfovich/socks5-client)
- [WSock Socks5 proxy forwarding POC](https://github.com/duketwo/WinsockConnectHookSocks5)
- [SOCKS Protocol Version 5](https://tools.ietf.org/html/rfc1928)
- [shadowsocks-windows](https://github.com/shadowsocks/shadowsocks-windows)
