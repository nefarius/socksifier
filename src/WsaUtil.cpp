#include "socksifier.h"

/**
 * \fn  static inline void LogWSAError()
 *
 * \brief   Send friendly name of WSA error message to default log.
 *
 * \author  Benjamin Höglinger-Stelzer
 * \date    23.07.2019
 */
void LogWSAError()
{
	char* error = nullptr;
	FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr,
		WSAGetLastError(),
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPSTR)&error, 0, nullptr);
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
BOOL BindAndConnectExSync(
	SOCKET s,
	const struct sockaddr* name,
	int namelen
)
{
	DWORD numBytes = 0, transfer = 0, flags = 0;
	OVERLAPPED overlapped = {0};
	overlapped.hEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);

	/* ConnectEx requires the socket to be initially bound. */
	{
		struct sockaddr_in addr;
		ZeroMemory(&addr, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = INADDR_ANY; // Any
		addr.sin_port = 0; // Any
		auto rc = real_bind(s, (SOCKADDR*)&addr, sizeof(addr));
		const auto error = WSAGetLastError();
		if (rc != 0 && error != WSAEINVAL /* socket might be already bound */)
		{
			spdlog::error("bind failed: {}", error);
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
		nullptr,
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
BOOL WSARecvSync(
	SOCKET s,
	PCHAR buffer,
	ULONG length
)
{
	DWORD flags = 0, transfer = 0, numBytes = 0;
	WSABUF recvBuf;
	OVERLAPPED overlapped = {0};
	overlapped.hEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);

	recvBuf.buf = buffer;
	recvBuf.len = length;

	if (WSARecv(s, &recvBuf, 1, &numBytes, &flags, &overlapped, nullptr) == SOCKET_ERROR)
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
BOOL WSASendSync(
	SOCKET s,
	PCHAR buffer,
	ULONG length
)
{
	DWORD flags = 0, transfer = 0, numBytes = 0;
	WSABUF sendBuf;
	OVERLAPPED overlapped = {0};
	overlapped.hEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);

	sendBuf.buf = buffer;
	sendBuf.len = length;

	if (WSASend(s, &sendBuf, 1, &numBytes, 0, &overlapped, nullptr) == SOCKET_ERROR)
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
