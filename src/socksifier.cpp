#include <winsock2.h>
#include <ws2tcpip.h>
#include <MSWSock.h>
#include <Windows.h>
#include "NtApi.h"

#include <map>

#include <detours/detours.h>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/msvc_sink.h>
#include <spdlog/fmt/bin_to_hex.h>

#pragma comment(lib, "Ws2_32.lib")


typedef struct settings {
    INT proxy_address;
    USHORT  proxy_port;
} setting_t;

static setting_t settings;

static std::map<SOCKET, SOCKADDR_IN> g_UdpRoutingMap;


#ifdef __cplusplus
extern "C" {
#endif

    static int (WINAPI * real_connect)(SOCKET s, const struct sockaddr * name, int namelen) = connect;

    static int (WINAPI * real_bind)(
        SOCKET         s,
        const sockaddr* addr,
        int            namelen
    ) = bind;

    static int (WINAPI * real_WSASendTo)(
        SOCKET                             s,
        LPWSABUF                           lpBuffers,
        DWORD                              dwBufferCount,
        LPDWORD                            lpNumberOfBytesSent,
        DWORD                              dwFlags,
        const sockaddr* lpTo,
        int                                iTolen,
        LPWSAOVERLAPPED                    lpOverlapped,
        LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    ) = WSASendTo;

    static int (WINAPI * real_WSARecvFrom)(
        SOCKET                             s,
        LPWSABUF                           lpBuffers,
        DWORD                              dwBufferCount,
        LPDWORD                            lpNumberOfBytesRecvd,
        LPDWORD                            lpFlags,
        sockaddr* lpFrom,
        LPINT                              lpFromlen,
        LPWSAOVERLAPPED                    lpOverlapped,
        LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    ) = WSARecvFrom;
	
    LPFN_CONNECTEX ConnectExPtr = NULL;

#ifdef __cplusplus
}
#endif


/**
 * \fn  static inline void LogWSAError()
 *
 * \brief   Send friendly name of WSA error message to default log.
 *
 * \author  Benjamin Höglinger-Stelzer
 * \date    23.07.2019
 */
static inline void LogWSAError()
{
    char *error = NULL;
    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        WSAGetLastError(),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&error, 0, NULL);
    spdlog::error("Winsock error details: {} ({})", error, WSAGetLastError());
    LocalFree(error);
}

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
        addr.sin_addr.s_addr = INADDR_ANY; // Any
        addr.sin_port = 0; // Any
        auto rc = bind(s, (SOCKADDR*)&addr, sizeof(addr));
        if (rc != 0) {
            spdlog::error("bind failed: {}", WSAGetLastError());
            LogWSAError();
            return FALSE;
        }
    }

    // 
    // Call ConnectEx with overlapped I/O
    // 
    if (!ConnectExPtr(
        s,
        name,
        namelen,
        NULL,
        0,
        &numBytes,
        &overlapped
    ) && WSAGetLastError() != WSA_IO_PENDING)
    {
        spdlog::error("ConnectEx failed: {}", WSAGetLastError());
        CloseHandle(overlapped.hEvent);
        return FALSE;
    }

    //
    // Wait for result
    // 
    const auto ret = WSAGetOverlappedResult(
        s,
        &overlapped,
        &transfer,
        TRUE,
        &flags
    );

    CloseHandle(overlapped.hEvent);
    return ret;
}

/**
 * \fn  static inline BOOL WSARecvSync( SOCKET s, PCHAR buffer, ULONG length )
 *
 * \brief   recv() in a blocking fashion.
 *
 * \author  Benjamin Höglinger-Stelzer
 * \date    23.07.2019
 *
 * \param   s       A SOCKET to process.
 * \param   buffer  The buffer.
 * \param   length  The length.
 *
 * \returns True if it succeeds, false if it fails.
 */
static inline BOOL WSARecvSync(
    SOCKET s,
    PCHAR buffer,
    ULONG length
)
{
    DWORD flags = 0, transfer = 0, numBytes = 0;
    WSABUF recvBuf;
    OVERLAPPED overlapped = { 0 };
    overlapped.hEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);

    recvBuf.buf = buffer;
    recvBuf.len = length;

    if (WSARecv(s, &recvBuf, 1, &numBytes, &flags, &overlapped, NULL) == SOCKET_ERROR)
    {
        if (WSAGetLastError() != WSA_IO_PENDING)
        {
            spdlog::error("WSARecv failed: {}", WSAGetLastError());
            CloseHandle(overlapped.hEvent);
            return FALSE;
        }
    }

    const auto ret = WSAGetOverlappedResult(
        s,
        &overlapped,
        &transfer,
        TRUE,
        &flags
    );

    CloseHandle(overlapped.hEvent);
    return ret;
}

/**
 * \fn  static inline BOOL WSASendSync( SOCKET s, PCHAR buffer, ULONG length )
 *
 * \brief   send() in a blocking fashion.
 *
 * \author  Benjamin Höglinger-Stelzer
 * \date    23.07.2019
 *
 * \param   s       A SOCKET to process.
 * \param   buffer  The buffer.
 * \param   length  The length.
 *
 * \returns True if it succeeds, false if it fails.
 */
static inline BOOL WSASendSync(
    SOCKET s,
    PCHAR buffer,
    ULONG length
)
{
    DWORD flags = 0, transfer = 0, numBytes = 0;
    WSABUF sendBuf;
    OVERLAPPED overlapped = { 0 };
    overlapped.hEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);

    sendBuf.buf = buffer;
    sendBuf.len = length;

    if (WSASend(s, &sendBuf, 1, &numBytes, 0, &overlapped, NULL) == SOCKET_ERROR)
    {
        if (WSAGetLastError() != WSA_IO_PENDING)
        {
            spdlog::error("WSASend failed: {}", WSAGetLastError());
            CloseHandle(overlapped.hEvent);
            return FALSE;
        }

    }

    const auto ret = WSAGetOverlappedResult(
        s,
        &overlapped,
        &transfer,
        TRUE,
        &flags
    );

    CloseHandle(overlapped.hEvent);
    return ret;
}

/**
 * \fn  int WINAPI my_connect(SOCKET s, const struct sockaddr * name, int namelen)
 *
 * \brief   Detoured connect function.
 *
 * \author  Benjamin Höglinger-Stelzer
 * \date    23.07.2019
 *
 * \param   s       A SOCKET to process.
 * \param   name    The name.
 * \param   namelen The namelen.
 *
 * \returns A WINAPI.
 */
int WINAPI my_connect(SOCKET s, const struct sockaddr * name, int namelen)
{
    auto logger = spdlog::get("socksifier")->clone("socksifier.connect");
	
    logger->debug("my_connect called");

    //
    // One-time initialization
    // 
    static std::once_flag flag;
    std::call_once(flag, [&sock = s]()
    {
        auto logger = spdlog::get("socksifier")->clone("socksifier.connect");
        logger->info("Requesting pointer to ConnectEx()");

        DWORD numBytes = 0;
        GUID guid = WSAID_CONNECTEX;

        //
        // Request ConnectEx function pointer
        // 
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
            logger->info("ConnectEx() pointer acquired");
        }
        else
        {
            logger->error("Failed to retrieve ConnectEx() pointer, error: {}", WSAGetLastError());
            ConnectExPtr = NULL;
        }
    });

    const struct sockaddr_in * dest = (const struct sockaddr_in *)name;

    char addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(dest->sin_addr), addr, INET_ADDRSTRLEN);
    const auto dest_port = ntohs(dest->sin_port);

    //
    // These destinations we don't usually wanna proxy
    // 
    if (ConnectExPtr == NULL || !strcmp(addr, "127.0.0.1") || !strcmp(addr, "0.0.0.0"))
    {
        return real_connect(s, name, namelen);
    }

    logger->info("Original connect destination: {}:{}", addr, dest_port);

    struct sockaddr_in proxy;
    proxy.sin_addr.s_addr = settings.proxy_address;
    proxy.sin_family = AF_INET;
    proxy.sin_port = settings.proxy_port;

    inet_ntop(AF_INET, &(proxy.sin_addr), addr, INET_ADDRSTRLEN);
    logger->info("Connecting to SOCKS proxy: {}:{}", addr, ntohs(proxy.sin_port));

    //
    // This handles non-blocking socket connections via extended Winsock API
    // 
    if (BindAndConnectExSync(
        s,
        reinterpret_cast<SOCKADDR *>(&proxy),
        sizeof(proxy)
    ))
    {
        logger->info("Proxy connection established");
    }
    else
    {
        logger->error("Proxy connection failed");
        LogWSAError();
        return SOCKET_ERROR;
    }

    //
    // Prepare greeting payload
    // 
    char greetProxy[3];
    greetProxy[0] = 0x05; // Version (always 0x05)
    greetProxy[1] = 0x01; // Number of authentication methods
    greetProxy[2] = 0x00; // NO AUTHENTICATION REQUIRED

    logger->info("Sending greeting to proxy");

    if (WSASendSync(s, greetProxy, sizeof(greetProxy)))
    {
        char response[2] = { 0 };

        if (WSARecvSync(s, response, sizeof(response))
            && response[0] == 0x05 /* expected version */
            && response[1] == 0x00 /* success value */)
        {
            logger->info("Proxy accepted greeting without authentication");
        }
        else
        {
            logger->error("Proxy greeting failed");
            LogWSAError();
            return SOCKET_ERROR;
        }
    }
    else
    {
        logger->error("Failed to greet SOCKS proxy server");
        LogWSAError();
        return SOCKET_ERROR;
    }

    //
    // Prepare remote connect request
    // 
    char remoteBind[10];
    remoteBind[0] = 0x05; // Version (always 0x05)
    remoteBind[1] = 0x01; // Connect command
    remoteBind[2] = 0x00; // Reserved
    remoteBind[3] = 0x01; // Type (IP V4 address)
    remoteBind[4] = (dest->sin_addr.s_addr >> 0) & 0xFF;
    remoteBind[5] = (dest->sin_addr.s_addr >> 8) & 0xFF;
    remoteBind[6] = (dest->sin_addr.s_addr >> 16) & 0xFF;
    remoteBind[7] = (dest->sin_addr.s_addr >> 24) & 0xFF;
    remoteBind[8] = (dest->sin_port >> 0) & 0xFF;
    remoteBind[9] = (dest->sin_port >> 8) & 0xFF;

    logger->info("Sending connect request to proxy");

    if (WSASendSync(s, remoteBind, sizeof(remoteBind)))
    {
        char response[10] = { 0 };

        if (WSARecvSync(s, response, sizeof(response))
            && response[1] == 0x00 /* success value */)
        {
            logger->info("Remote connection established");
        }
        else
        {
            logger->error("Consuming proxy response failed");
            LogWSAError();
            return SOCKET_ERROR;
        }
    }
    else
    {
        logger->error("Failed to instruct proxy to remote connect");
        LogWSAError();
        return SOCKET_ERROR;
    }

    return ERROR_SUCCESS;
}

int WINAPI my_bind(
    SOCKET         s,
    const sockaddr* addr,
    int            namelen
)
{
    auto logger = spdlog::get("socksifier")->clone("socksifier.bind");
	
    logger->debug("my_bind called ({})", s);

    int optType = -1;
    int optLen = sizeof(int);

	//
	// We need to know the socket type
	// 	
    if (getsockopt(s, SOL_SOCKET, SO_TYPE, reinterpret_cast<PCHAR>(&optType), &optLen) != 0)
        return real_bind(s, addr, namelen);
        
    const struct sockaddr_in* dest = (const struct sockaddr_in*)addr;

	//
	// Not of interest to intercept
	// 
    if (optType != SOCK_DGRAM || g_UdpRoutingMap.count(s))
	    return real_bind(s, addr, namelen);

    logger->info("Binding UDP socket, tracking socket handle");

    SOCKET sTun = INVALID_SOCKET;
	
    do
    {
	    //
	    // Create and bind temporary TCP socket for SOCKS5 handshake
	    // 

    	sTun = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	    if (sTun == INVALID_SOCKET)
	    {
            logger->error("socket failed: {}", WSAGetLastError());
            LogWSAError();
		    break;
	    }

        SOCKADDR_IN tbAddr;
        ZeroMemory(&tbAddr, sizeof(tbAddr));
        tbAddr.sin_family = AF_INET;
        tbAddr.sin_addr.s_addr = INADDR_ANY; // Any
        tbAddr.sin_port = 0; // Any

    	auto rc = real_bind(sTun, reinterpret_cast<SOCKADDR*>(&tbAddr), sizeof(tbAddr));
    	
        if (rc != 0) 
        {
            logger->error("bind failed: {}", WSAGetLastError());
            LogWSAError();
            break;
        }

        SOCKADDR_IN proxy;
        proxy.sin_addr.s_addr = settings.proxy_address;
        proxy.sin_family = AF_INET;
        proxy.sin_port = settings.proxy_port;

        rc = real_connect(sTun, reinterpret_cast<SOCKADDR*>(&proxy), sizeof(proxy));

        if (rc != 0)
        {
            logger->error("connect failed: {}", WSAGetLastError());
            LogWSAError();
            break;
        }

	    //
	    // Prepare greeting payload
	    // 
	    char greetProxy[3];
	    greetProxy[0] = 0x05; // Version (always 0x05)
	    greetProxy[1] = 0x01; // Number of authentication methods
	    greetProxy[2] = 0x00; // NO AUTHENTICATION REQUIRED

        logger->info("Sending greeting to proxy");

	    if (send(sTun, greetProxy, sizeof(greetProxy), 0) != sizeof(greetProxy))
	    {
            logger->error("Proxy greeting failed");
		    LogWSAError();
		    break;
	    }

	    char response[2] = {0};

	    if (recv(sTun, response, sizeof(response), 0)
		    && response[0] == 0x05 /* expected version */
		    && response[1] == 0x00 /* success value */)
	    {
            logger->info("Proxy accepted greeting without authentication");
	    }
	    else
	    {
            logger->error("Proxy greeting failed");
		    LogWSAError();
		    break;
	    }

        //
        // Prepare remote connect request
        // 
        char udpAssociate[10];
        ZeroMemory(udpAssociate, ARRAYSIZE(udpAssociate));
        udpAssociate[0] = 0x05; // Version (always 0x05)
        udpAssociate[1] = 0x03; // UDP ASSOCIATE command
        udpAssociate[2] = 0x00; // Reserved
        udpAssociate[3] = 0x01; // Type (IP V4 address)
    	//
    	// TODO: this doesn't really matter, as Shadowsocks uses
    	// the encapsulated UDP header to determine the real
    	// remote endpoint to use.
    	// 
        udpAssociate[4] = (dest->sin_addr.s_addr >> 0) & 0xFF;
        udpAssociate[5] = (dest->sin_addr.s_addr >> 8) & 0xFF;
        udpAssociate[6] = (dest->sin_addr.s_addr >> 16) & 0xFF;
        udpAssociate[7] = (dest->sin_addr.s_addr >> 24) & 0xFF;
        udpAssociate[8] = (dest->sin_port >> 0) & 0xFF;
        udpAssociate[9] = (dest->sin_port >> 8) & 0xFF;

        logger->info("Sending UDP ASSOCIATE to proxy");

    	//
    	// Request UDP relay endpoint
    	// 
        if (send(sTun, udpAssociate, sizeof(udpAssociate), 0) != sizeof(udpAssociate))
        {
            logger->error("UDP ASSOCIATE failed");
            LogWSAError();
            break;
        }

        char udpAssociateResp[10] = { 0 };

    	//
    	// Parse response, contains endpoint
    	// 
        if (recv(sTun, udpAssociateResp, sizeof(udpAssociateResp), 0)
            && response[1] == 0x00 /* success value */)
        {
        	//
        	// This is the endpoint the UDP relay is listening on
        	// 
            SOCKADDR_IN udpEndpoint;
            udpEndpoint.sin_addr.s_addr = (
                udpAssociateResp[4] << 0 | 
                udpAssociateResp[5] << 8 | 
                udpAssociateResp[6] << 16 | 
                udpAssociateResp[7] << 24
                );
            udpEndpoint.sin_port = (udpAssociateResp[8] << 0 | udpAssociateResp[9] << 8);
            udpEndpoint.sin_family = dest->sin_family;
        	
            char address[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(udpEndpoint.sin_addr), address, INET_ADDRSTRLEN);
            const auto dest_port = ntohs(udpEndpoint.sin_port);

            logger->info("Received UDP relay endpoint {}:{} for socket {}",
                address, dest_port, s);

            //
	        // Keep track to start forwarding in my_WSASendTo
	        // 
            g_UdpRoutingMap.insert(std::pair<SOCKET, SOCKADDR_IN>(s, udpEndpoint));
        }
        else
        {
            logger->error("UDP ASSOCIATE response failed");
            LogWSAError();
            break;
        }
    }
    while (FALSE);

	//
	// Not required anymore after we got the new endpoint
	// 
    if (sTun != INVALID_SOCKET)
	    closesocket(sTun);
	
    return real_bind(s, addr, namelen);
}

//
// Intercepts https://chromium.googlesource.com/chromium/src/+/refs/heads/main/net/socket/udp_socket_win.cc#837
// 
int WINAPI my_WSASendTo(
    SOCKET                             s,
    LPWSABUF                           lpBuffers,
    DWORD                              dwBufferCount,
    LPDWORD                            lpNumberOfBytesSent,
    DWORD                              dwFlags,
    const sockaddr* lpTo,
    int                                iTolen,
    LPWSAOVERLAPPED                    lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
)
{
    auto logger = spdlog::get("socksifier")->clone("socksifier.udp.WSASendTo");

    PSOCKADDR_IN dest = (PSOCKADDR_IN)lpTo;
	
    do
    {
	    //
	    // TCP tunnel through SOCKS5 exists for this socket
	    // 
	    if (!g_UdpRoutingMap.count(s))
		    break;

	    PSOCKADDR_IN sTun = &g_UdpRoutingMap[s];
	    WSABUF destBuffer;
        DWORD num;

    	//
    	// Allocate new buffer with enough space to origin header
    	// 
	    destBuffer.len = lpBuffers->len + 10;
	    destBuffer.buf = static_cast<PCHAR>(malloc(destBuffer.len));

	    if (destBuffer.buf == nullptr)
		    break;

	    ZeroMemory(destBuffer.buf, destBuffer.len);

	    destBuffer.buf[3] = 0x01; // IP V4 address
	    destBuffer.buf[4] = (dest->sin_addr.s_addr >> 0) & 0xFF;
	    destBuffer.buf[5] = (dest->sin_addr.s_addr >> 8) & 0xFF;
	    destBuffer.buf[6] = (dest->sin_addr.s_addr >> 16) & 0xFF;
	    destBuffer.buf[7] = (dest->sin_addr.s_addr >> 24) & 0xFF;
	    destBuffer.buf[8] = (dest->sin_port >> 0) & 0xFF;
	    destBuffer.buf[9] = (dest->sin_port >> 8) & 0xFF;

	    memcpy(&destBuffer.buf[10], lpBuffers->buf, lpBuffers->len);

        char originAddr[INET_ADDRSTRLEN], relayAddr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(dest->sin_addr), originAddr, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(sTun->sin_addr), relayAddr, INET_ADDRSTRLEN);
    	
        logger->debug("Relaying UDP packet for {}:{} to {}:{}",
            originAddr, ntohs(dest->sin_port), relayAddr, ntohs(sTun->sin_port));
    	
	    const auto ret = real_WSASendTo(
		    s,
		    &destBuffer,
		    1,
		    &num,
		    0,
		    reinterpret_cast<const PSOCKADDR>(sTun),
		    sizeof(*sTun),
		    lpOverlapped,
		    lpCompletionRoutine
	    );

        free(destBuffer.buf);
        return ret;
    }
    while (FALSE);    

    char addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(dest->sin_addr), addr, INET_ADDRSTRLEN);
    const auto dest_port = ntohs(dest->sin_port);

	logger->debug("Sending packet to origin {}:{}", addr, dest_port);
    
    return real_WSASendTo(
        s,
        lpBuffers,
        dwBufferCount,
        lpNumberOfBytesSent,
        dwFlags,
        lpTo, 
        iTolen,
        lpOverlapped,
        lpCompletionRoutine
    );
}

//
// Intercepts https://chromium.googlesource.com/chromium/src/+/refs/heads/main/net/socket/udp_socket_win.cc#778
// 
int WINAPI my_WSARecvFrom(
    SOCKET                             s,
    LPWSABUF                           lpBuffers,
    DWORD                              dwBufferCount,
    LPDWORD                            lpNumberOfBytesRecvd,
    LPDWORD                            lpFlags,
    sockaddr* lpFrom,
    LPINT                              lpFromlen,
    LPWSAOVERLAPPED                    lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
)
{
    auto logger = spdlog::get("socksifier")->clone("socksifier.udp.WSARecvFrom");

    const struct sockaddr_in* dest = (const struct sockaddr_in*)lpFrom;

    char addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(dest->sin_addr), addr, INET_ADDRSTRLEN);
    const auto dest_port = ntohs(dest->sin_port);

    logger->debug("Received UDP packet from {}:{}", addr, dest_port);

	//
	// TODO: better error checking, works with CEF (as of now)
	// 
    const auto ret = real_WSARecvFrom(
        s,
        lpBuffers,
        dwBufferCount,
        lpNumberOfBytesRecvd,
        lpFlags,
        lpFrom,
        lpFromlen,
        lpOverlapped,
        lpCompletionRoutine
    );
    
    do
    {
        if (!g_UdpRoutingMap.count(s))
            break;
                
        logger->debug("Relayed socket, stripping UDP header");

#ifdef _DBG
        const std::vector<char> aBuffer(lpBuffers->buf, lpBuffers->buf + *lpNumberOfBytesRecvd);
        logger->debug("({:04d}) -> {:Xpn}",
            *lpNumberOfBytesRecvd,
            spdlog::to_hex(aBuffer)
        );
#endif

    	//
    	// Skip the UDP encapsulation header and adjust packet size
    	// 
        memmove(lpBuffers->buf, &lpBuffers->buf[10], *lpNumberOfBytesRecvd -= 10);

#ifdef _DBG
        const std::vector<char> bBuffer(lpBuffers->buf, lpBuffers->buf + *lpNumberOfBytesRecvd);
        logger->debug("({:04d}) -> {:Xpn}",
            *lpNumberOfBytesRecvd,
            spdlog::to_hex(bBuffer)
        );
#endif
    	
    } while (FALSE);

    return ret;
}


LPWSTR GetObjectName(HANDLE hObject)
{
	LPWSTR lpwsReturn = nullptr;
	const auto pNTQO = reinterpret_cast<tNtQueryObject>(GetProcAddress(
		GetModuleHandle("NTDLL.DLL"),
		"NtQueryObject"
	));

	if (pNTQO != nullptr)
	{
		DWORD dwSize = sizeof(OBJECT_NAME_INFORMATION);
		POBJECT_NAME_INFORMATION pObjectInfo = (POBJECT_NAME_INFORMATION)new BYTE[dwSize];
		NTSTATUS ntReturn = pNTQO(hObject, ObjectNameInformation, pObjectInfo, dwSize, &dwSize);

		if (ntReturn == STATUS_BUFFER_OVERFLOW)
		{
			delete pObjectInfo;
			pObjectInfo = (POBJECT_NAME_INFORMATION)new BYTE[dwSize];
			ntReturn = pNTQO(hObject, ObjectNameInformation, pObjectInfo, dwSize, &dwSize);
		}

		if ((ntReturn >= STATUS_SUCCESS) && (pObjectInfo->Buffer != nullptr))
		{
			lpwsReturn = (LPWSTR)new BYTE[pObjectInfo->Length + sizeof(WCHAR)];
			ZeroMemory(lpwsReturn, pObjectInfo->Length + sizeof(WCHAR));
			CopyMemory(lpwsReturn, pObjectInfo->Buffer, pObjectInfo->Length);
		}

		delete pObjectInfo;
	}

	return lpwsReturn;
}

LPWSTR GetObjectTypeName(HANDLE hObject)
{
	LPWSTR lpwsReturn = nullptr;
	const auto pNTQO = reinterpret_cast<tNtQueryObject>(GetProcAddress(
		GetModuleHandle("NTDLL.DLL"),
		"NtQueryObject"
	));

	if (pNTQO != nullptr)
	{
		DWORD dwSize = sizeof(PUBLIC_OBJECT_TYPE_INFORMATION);
		PPUBLIC_OBJECT_TYPE_INFORMATION pObjectInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)new BYTE[dwSize];
		NTSTATUS ntReturn = pNTQO(hObject, ObjectTypeInformation, pObjectInfo, dwSize, &dwSize);

		if (ntReturn == STATUS_BUFFER_OVERFLOW || ntReturn == STATUS_INFO_LENGTH_MISMATCH)
		{
			delete pObjectInfo;
			pObjectInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)new BYTE[dwSize];
			ntReturn = pNTQO(hObject, ObjectTypeInformation, pObjectInfo, dwSize, &dwSize);
		}

		if ((ntReturn >= STATUS_SUCCESS) && (pObjectInfo->TypeName.Buffer != nullptr))
		{
			lpwsReturn = (LPWSTR)new BYTE[pObjectInfo->TypeName.Length + sizeof(WCHAR)];
			ZeroMemory(lpwsReturn, pObjectInfo->TypeName.Length + sizeof(WCHAR));
			CopyMemory(lpwsReturn, pObjectInfo->TypeName.Buffer, pObjectInfo->TypeName.Length);
		}

		delete pObjectInfo;
	}

	return lpwsReturn;
}

//
// Finds and kills existing TCP connections within this process
// 
DWORD WINAPI SocketEnumMainThread(LPVOID Params)
{
	UNREFERENCED_PARAMETER(Params);

	auto pid = GetCurrentProcessId();

    spdlog::info("Attempting to reap open connections for PID {}", pid);

	WSAPROTOCOL_INFOW wsaProtocolInfo = {0};

	const auto pNTQSI = reinterpret_cast<tNtQuerySystemInformation>(GetProcAddress(
		GetModuleHandle("NTDLL.DLL"),
		"NtQuerySystemInformation"
	));

	if (pNTQSI == nullptr)
	{
		spdlog::error("Failed to acquire NtQuerySystemInformation API");
		return 1;
	}

	DWORD dwSize = sizeof(SYSTEM_HANDLE_INFORMATION);

	auto* pHandleInfo = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(new BYTE[dwSize]);

	NTSTATUS ntReturn = pNTQSI(SystemHandleInformation, pHandleInfo, dwSize, &dwSize);

	//
	// Get required buffer size for all handle meta-data
	// 
	while (ntReturn == STATUS_INFO_LENGTH_MISMATCH)
	{
		delete pHandleInfo;

		//
		// The handle count can change between these calls, so just
		// allocate a bit more memory and it should be fine!
		// 
		dwSize += 1024;

		pHandleInfo = (PSYSTEM_HANDLE_INFORMATION)new BYTE[dwSize];

		ntReturn = pNTQSI(SystemHandleInformation, pHandleInfo, dwSize, &dwSize);
	}

	if (ntReturn != STATUS_SUCCESS)
	{
		spdlog::error("NtQuerySystemInformation failed with status {}", ntReturn);
		return 1;
	}

	//
	// Walk all handles
	// 
	for (DWORD dwIdx = 0; dwIdx < pHandleInfo->NumberOfHandles; dwIdx++)
	{
		const PSYSTEM_HANDLE_TABLE_ENTRY_INFO pEntry = &pHandleInfo->Handles[dwIdx];

		//
		// Skip processes other than ours
		// 
		if (pEntry->UniqueProcessId != pid)
			continue;

		auto* handle = reinterpret_cast<HANDLE>(pHandleInfo->Handles[dwIdx].HandleValue);

		//
		// Attempt to get object name
		// 
		LPCWSTR objectName = GetObjectName(handle);

		if (objectName == nullptr)
			continue;

		//
		// Check if handle belongs to "Ancillary Function Driver" (network stack)
		// 
		if (wcscmp(objectName, L"\\Device\\Afd") != 0)
		{
            delete objectName;
			continue;
		}

        delete objectName;
		
		spdlog::info("Found open socket, attempting duplication");

		//
		// Duplication is both a validity check and useful for logging
		// 
		const NTSTATUS status = WSADuplicateSocketW(
			reinterpret_cast<SOCKET>(handle),
			GetCurrentProcessId(),
			&wsaProtocolInfo
		);

		if (status != STATUS_SUCCESS)
		{
			//
			// Not a socket handle, ignore
			// 
			if (WSAGetLastError() == WSAENOTSOCK)
				continue;

			spdlog::warn("Couldn't duplicate, moving on");
			LogWSAError(); // For diagnostics, ignore otherwise
			continue;
		}

		//
		// Create new duplicated socket
		// 
		const SOCKET targetSocket = WSASocketW(
			wsaProtocolInfo.iAddressFamily,
			wsaProtocolInfo.iSocketType,
			wsaProtocolInfo.iProtocol,
			&wsaProtocolInfo,
			0,
			WSA_FLAG_OVERLAPPED
		);

		if (targetSocket != INVALID_SOCKET)
		{
			struct sockaddr_in sockaddr;
			int len = sizeof(SOCKADDR_IN);

			// 
			// This call should succeed now
			// 
			if (getpeername(targetSocket, reinterpret_cast<SOCKADDR*>(&sockaddr), &len) == 0)
			{
				char addr[INET_ADDRSTRLEN];
				ZeroMemory(addr, ARRAYSIZE(addr));
				inet_ntop(AF_INET, &(sockaddr.sin_addr), addr, INET_ADDRSTRLEN);

				spdlog::info("Duplicated socket {}, closing", addr);

				//
				// Close duplicate
				// 
				closesocket(targetSocket);

				//
				// Terminate original socket
				// 
				CloseHandle(handle);
			}
			else LogWSAError(); // For diagnostics, ignore otherwise
		}
		else LogWSAError(); // For diagnostics, ignore otherwise
	}

	delete pHandleInfo;

	return 0;
}


BOOL WINAPI DllMain(HINSTANCE dll_handle, DWORD reason, LPVOID reserved)
{
	if (DetourIsHelperProcess())
	{
		return TRUE;
	}

	switch (reason)
	{
	case DLL_PROCESS_ATTACH:

		{
			//
			// Observe best with https://github.com/CobaltFusion/DebugViewPP
			// 
			auto sink = std::make_shared<spdlog::sinks::msvc_sink_mt>();
			sink->set_level(spdlog::level::info);

			auto logger = std::make_shared<spdlog::logger>("socksifier", sink);

			spdlog::set_level(spdlog::level::info);
			logger->flush_on(spdlog::level::info);

			set_default_logger(logger);

			//
			// Default values
			// 
			CHAR addressVar[MAX_PATH] = "127.0.0.1";
			CHAR portVar[MAX_PATH] = "1080";

			//
			// Mandatory variables
			// 
			GetEnvironmentVariableA("SOCKSIFIER_ADDRESS", addressVar, ARRAYSIZE(addressVar));
			GetEnvironmentVariableA("SOCKSIFIER_PORT", portVar, ARRAYSIZE(portVar));

			inet_pton(AF_INET, addressVar, &settings.proxy_address);
			settings.proxy_port = _byteswap_ushort(static_cast<USHORT>(strtol(portVar, nullptr, 10)));

			spdlog::info("Using SOCKS proxy: {}:{}", addressVar, portVar);
		}

		DisableThreadLibraryCalls(dll_handle);
		DetourRestoreAfterWith();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&static_cast<PVOID>(real_connect), my_connect);
        DetourAttach(&static_cast<PVOID>(real_bind), my_bind);
        DetourAttach(&static_cast<PVOID>(real_WSASendTo), my_WSASendTo);
        DetourAttach(&static_cast<PVOID>(real_WSARecvFrom), my_WSARecvFrom);
		DetourTransactionCommit();

		//
		// Start socket enumeration in new thread
		// 
		/*CreateThread(
			nullptr,
			0,
			reinterpret_cast<LPTHREAD_START_ROUTINE>(SocketEnumMainThread),
			nullptr,
			0,
			nullptr
		);*/
		
		break;

	case DLL_PROCESS_DETACH:
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&static_cast<PVOID>(real_connect), my_connect);
        DetourDetach(&static_cast<PVOID>(real_bind), my_bind);
        DetourDetach(&static_cast<PVOID>(real_WSASendTo), my_WSASendTo);
        DetourDetach(&static_cast<PVOID>(real_WSARecvFrom), my_WSARecvFrom);
		DetourTransactionCommit();
		break;
	}
	return TRUE;
}
