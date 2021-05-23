#pragma once

//
// WinAPI
// 
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <MSWSock.h>
#include <Windows.h>

//
// Custom
// 
#include "NtApi.h"
#include "NtUtil.h"
#include "WsaUtil.h"

//
// STL
// 
#include <map>

//
// Logging
// 
#include <spdlog/spdlog.h>
#include <spdlog/sinks/msvc_sink.h>
#include <spdlog/fmt/bin_to_hex.h>

typedef struct settings
{
	INT proxy_address;
	USHORT proxy_port;
} setting_t;

extern LPFN_CONNECTEX ConnectExPtr;

extern setting_t g_Settings;

extern std::map<SOCKET, SOCKADDR_IN> g_UdpRoutingMap;

EXTERN_C int (WINAPI* real_connect)(SOCKET s, const struct sockaddr* name, int namelen);

EXTERN_C int (WINAPI* real_bind)(
	SOCKET s,
	const sockaddr* addr,
	int namelen
	);

EXTERN_C int (WINAPI* real_WSASendTo)(
	SOCKET s,
	LPWSABUF lpBuffers,
	DWORD dwBufferCount,
	LPDWORD lpNumberOfBytesSent,
	DWORD dwFlags,
	const sockaddr* lpTo,
	int iTolen,
	LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
	);

EXTERN_C int (WINAPI* real_WSARecvFrom)(
	SOCKET s,
	LPWSABUF lpBuffers,
	DWORD dwBufferCount,
	LPDWORD lpNumberOfBytesRecvd,
	LPDWORD lpFlags,
	sockaddr* lpFrom,
	LPINT lpFromlen,
	LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
	);

EXTERN_C int (WINAPI* real_closesocket)(
	SOCKET s
	);
