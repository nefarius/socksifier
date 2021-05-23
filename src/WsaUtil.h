#pragma once

void LogWSAError();

BOOL BindAndConnectExSync(
	SOCKET s,
	const struct sockaddr* name,
	int namelen
);

BOOL WSARecvSync(
	SOCKET s,
	PCHAR buffer,
	ULONG length
);

BOOL WSASendSync(
	SOCKET s,
	PCHAR buffer,
	ULONG length
);
