# Socksifier

A windows DLL which hook the `connect()` std call to redirect sockets to SOCKS4 proxy server.

## Build

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
