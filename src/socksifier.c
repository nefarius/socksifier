#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "minhook.h"

#pragma comment(lib, "Ws2_32.lib")

#define USER_ID "socksifier"

typedef struct settings {
    int proxy_address;
    short proxy_port;
} setting_t;

static setting_t settings = {
    .proxy_address = 0x0100007F,
    .proxy_port = 0x3804
};

__declspec(dllexport) void set_proxy_address(void * args)
{
    settings.proxy_address = *((int *)args);
}

__declspec(dllexport) void set_proxy_port(void * args)
{
    settings.proxy_port = *((short *)args);
}

int (WINAPI * real_connect)(SOCKET s, const struct sockaddr * name, int namelen) = NULL;

int WINAPI my_connect(SOCKET s, const struct sockaddr * name, int namelen)
{
    const struct sockaddr_in * dest = (const struct sockaddr_in *)name;

    struct sockaddr_in proxy;
    proxy.sin_addr.s_addr = settings.proxy_address;
    proxy.sin_family = AF_INET;
    proxy.sin_port = settings.proxy_port;
    int ret = real_connect(s, (const struct sockaddr *)&proxy, sizeof(proxy));
    if (ret) {
        return ret;
    }

    char buffer[256];
    buffer[0] = 0x04;
    buffer[1] = 0x01;
    buffer[2] = (dest->sin_port >> 0) & 0xFF;
    buffer[3] = (dest->sin_port >> 8) & 0xFF;
    buffer[4] = (dest->sin_addr.s_addr >>  0) & 0xFF;
    buffer[5] = (dest->sin_addr.s_addr >>  8) & 0xFF;
    buffer[6] = (dest->sin_addr.s_addr >> 16) & 0xFF;
    buffer[7] = (dest->sin_addr.s_addr >> 24) & 0xFF;
    sprintf_s(&buffer[8], 256 - 8, "%s", USER_ID);
    send(s, buffer, 8 + strlen(USER_ID), 0);

    recv(s, buffer, 8, 0);
    if (buffer[1] != 0x5A) {
        return SOCKET_ERROR;
    }

    return ret;
}


BOOL WINAPI DllMain(HINSTANCE dll_handle, DWORD reason, LPVOID reserved) 
{
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(dll_handle);
            MH_Initialize();
            MH_CreateHookApiEx(L"ws2_32", "connect", (LPVOID *)&my_connect,
                                                     (LPVOID *)&real_connect, NULL);
            MH_EnableHook(MH_ALL_HOOKS);
            break;

        case DLL_PROCESS_DETACH:
            MH_DisableHook(MH_ALL_HOOKS);
            MH_Uninitialize();
            break;
    }
    return TRUE;
}
