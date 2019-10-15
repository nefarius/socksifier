# Socksifier

A windows DLL which hook the `connect()` std call to redirect sockets to SOCKS5 proxy server.

[![Build status](https://ci.appveyor.com/api/projects/status/bwesvx70s524t30w/branch/master?svg=true)](https://ci.appveyor.com/project/nefarius/socksifier/branch/master)

## Build

[Follow the Vcpkg Quick Start](https://github.com/Microsoft/vcpkg#quick-start) and install the following packages:

- `.\vcpkg install spdlog:x86-windows-static spdlog:x64-windows-static detours:x86-windows-static detours:x64-windows-static`

This project use the NMAKE version of makefile. To build the DLL, simply open your `Developper Command Prompt for Visual Studio` and use:
 - `nmake` to build
 - `nmake clean` to clean

## Getting started

To enable the redirection you just have to inject the DLL in your target process.

By default, socksfier redirect sockets to `localhost:1080` but these values can be set by using the exported functions `set_proxy_address()` and `set_proxy_port()`.

To call these functions and use your own configuration you need a DLL injector which allow you to calls these functions. For example with [this one](https://github.com/numaru/injector), I can change the default port to `9050`.

```python
proxy_addr = socket.inet_aton("127.0.0.1")
proxy_port = struct.pack("!H", 9050)

# ...

dll_addr = injector.inject_dll(path_dll)
injector.call_from_injected(path_dll, dll_addr, "set_proxy_address", proxy_addr)
injector.call_from_injected(path_dll, dll_addr, "set_proxy_port", proxy_port)
injector.unload()
```

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
