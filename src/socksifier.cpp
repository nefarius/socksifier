#include <winsock2.h>
#include <ws2tcpip.h>
#include <MSWSock.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include <detours.h>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>

#pragma comment(lib, "Ws2_32.lib")

#define USER_ID "socksifier"

typedef struct settings {
    int proxy_address;
    short proxy_port;
} setting_t;

static setting_t settings;

#ifdef __cplusplus
extern "C" {
#endif

    __declspec(dllexport) void set_proxy_address(void * args)
    {
        settings.proxy_address = *((int *)args);
    }

    __declspec(dllexport) void set_proxy_port(void * args)
    {
        settings.proxy_port = *((short *)args);
    }

    static int (WINAPI * real_connect)(SOCKET s, const struct sockaddr * name, int namelen) = connect;

    LPFN_CONNECTEX ConnectExPtr = NULL;

#ifdef __cplusplus
}
#endif

/**
 * \fn  static inline BOOL BindAndConnectExSync( SOCKET s, const struct sockaddr * name, int namelen )
 *
 * \brief   Bind and connect a non-blocking socket synchronously.
 *
 * \author  Benjamin Höglinger-Stelzer
 * \date    23.07.2019
 *
 * \param   s       A SOCKET to process.
 * \param   name    The const struct sockaddr *.
 * \param   namelen The sizeof(const struct sockaddr).
 *
 * \returns True if it succeeds, false if it fails.
 */
static inline BOOL BindAndConnectExSync(
    SOCKET s,
    const struct sockaddr * name,
    int namelen
)
{
    DWORD numBytes = 0, transfer = 0, flags = 0;
    OVERLAPPED overlapped = { 0 };
    overlapped.hEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);

    /* ConnectEx requires the socket to be initially bound. */
    {
        struct sockaddr_in addr;
        ZeroMemory(&addr, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = 0;
        auto rc = bind(s, (SOCKADDR*)&addr, sizeof(addr));
        if (rc != 0) {
            spdlog::error("bind failed: {}", WSAGetLastError());
            return 1;
        }
    }

    // TODO: error handling
    auto retval = ConnectExPtr(
        s,
        name,
        namelen,
        NULL,
        0,
        &numBytes,
        &overlapped
    );

    return WSAGetOverlappedResult(
        s,
        &overlapped,
        &transfer,
        TRUE,
        &flags
    );
}

int WINAPI my_connect(SOCKET s, const struct sockaddr * name, int namelen)
{
    spdlog::debug("my_connect called");

    static std::once_flag flag;
    std::call_once(flag, [&sock = s]()
    {
        spdlog::info("Requesting pointer to ConnectEx()");

        DWORD numBytes = 0;
        GUID guid = WSAID_CONNECTEX;

        const auto ret = WSAIoctl(
            sock,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            (void*)&guid,
            sizeof(guid),
            (void*)&ConnectExPtr,
            sizeof(ConnectExPtr),
            &numBytes,
            NULL,
            NULL
        );

        if (!ret)
        {
            spdlog::info("ConnectEx() pointer acquired");
        }
        else
        {
            spdlog::error("Failed to retrieve ConnectEx() pointer, error: {}", WSAGetLastError());
        }
    });

    const struct sockaddr_in * dest = (const struct sockaddr_in *)name;

    char addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(dest->sin_addr), addr, INET_ADDRSTRLEN);
    const auto dest_port = ntohs(dest->sin_port);
    spdlog::info("Original connect destination: {}:{}", addr, dest_port);

    if (dest_port != 443)
    {
        return real_connect(s, name, namelen);
    }

    struct sockaddr_in proxy;
    proxy.sin_addr.s_addr = settings.proxy_address;
    proxy.sin_family = AF_INET;
    proxy.sin_port = settings.proxy_port;

    inet_ntop(AF_INET, &(proxy.sin_addr), addr, INET_ADDRSTRLEN);
    spdlog::info("Connecting to SOCKS proxy: {}:{}", addr, ntohs(proxy.sin_port));


    auto retv = BindAndConnectExSync(
        s,
        reinterpret_cast<SOCKADDR *>(&proxy),
        sizeof(proxy)
    );


    //const int ret = real_connect(s, reinterpret_cast<SOCKADDR *>(&proxy), sizeof(proxy));
    //if (ret) {
    //    char *error = NULL;
    //    FormatMessageA(
    //        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
    //        NULL,
    //        WSAGetLastError(),
    //        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
    //        (LPSTR)&error, 0, NULL);
    //    spdlog::error("Proxy server connection failed: {} ({})", error, WSAGetLastError());
    //    LocalFree(error);
    //
    //    return ret;
    //}

    char buffer[256];
    ZeroMemory(buffer, 256);
    buffer[0] = 0x05; // protocol version: X'05'
    buffer[1] = 0x01; // CONNECT X'01'
    buffer[2] = 0x00; // RESERVED
    buffer[3] = 0x01; //IP V4 address: X'01'

    buffer[4] = (dest->sin_addr.s_addr >> 0) & 0xFF;
    buffer[5] = (dest->sin_addr.s_addr >> 8) & 0xFF;
    buffer[6] = (dest->sin_addr.s_addr >> 16) & 0xFF;
    buffer[7] = (dest->sin_addr.s_addr >> 24) & 0xFF;
    buffer[8] = (dest->sin_port >> 0) & 0xFF;
    buffer[9] = (dest->sin_port >> 8) & 0xFF;

    auto b = send(s, buffer, 10, 0);

    DWORD flags = 0, transfer = 0, numBytes = 0;
    WSABUF recvBuf;
    OVERLAPPED overlapped = { 0 };
    overlapped.hEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);

    ZeroMemory(buffer, 256);
    recvBuf.buf = buffer;
    recvBuf.len = 256;

    if (WSARecv(s, &recvBuf, 1, &numBytes, &flags, &overlapped, NULL) == SOCKET_ERROR)
    {
        if (WSAGetLastError() != WSA_IO_PENDING)
        {

            // Error occurred

        }

    }

    auto rv = WSAGetOverlappedResult(
        s,
        &overlapped,
        &transfer,
        TRUE,
        &flags
    );

    auto v = WSAGetLastError();



    return 0;
}


BOOL WINAPI DllMain(HINSTANCE dll_handle, DWORD reason, LPVOID reserved)
{
    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    switch (reason) {
    case DLL_PROCESS_ATTACH:
        settings.proxy_address = 0x0100007F; // 127.0.0.1
        settings.proxy_port = 0x3804; // 1080

        {
            auto logger = spdlog::basic_logger_mt(
                "socksifier",
                "socksifier.log"
            );

#if _DEBUG
            spdlog::set_level(spdlog::level::debug);
            logger->flush_on(spdlog::level::debug);
#else
            logger->flush_on(spdlog::level::info);
#endif

            spdlog::set_default_logger(logger);
        }

        DisableThreadLibraryCalls(dll_handle);
        DetourRestoreAfterWith();

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID)real_connect, my_connect);
        DetourTransactionCommit();

        break;

    case DLL_PROCESS_DETACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID)real_connect, my_connect);
        DetourTransactionCommit();
        break;
    }
    return TRUE;
}
