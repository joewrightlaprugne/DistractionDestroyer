/******************************************************************************
  PacketFilter.h  - PacketFilter class declaration.

                                                 Mahesh S
                                                 swatkat_thinkdigit@yahoo.co.in
                                                 http://swatrant.blogspot.com/


******************************************************************************/

#ifndef _PACKETFILTER_H_
#define _PACKETFILTER_H_

//#define SAMPLE_APP  // Comment this line to disable the main().
#pragma comment(lib, "Fwpuclnt.lib")
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "ws2_32.lib")

// Standard includes.
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#include <Winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <strsafe.h>
#include <ws2tcpip.h>
#include <fwpmu.h>
#include <list>
#include <iostream>
using namespace std;

// Firewall sub-layer names.
#define FIREWALL_SUBLAYER_NAME  "MyVistaFirewall"
#define FIREWALL_SUBLAYER_NAMEW L"MyVistaFirewall"
#define FIREWALL_SERVICE_NAMEW  FIREWALL_SUBLAYER_NAMEW

// Byte array IP address length
#define BYTE_IPADDR_ARRLEN    4

// String format IP address length
#define STR_IPADDR_LEN        32

// Vista subnet mask
#define VISTA_SUBNET_MASK   0xffffffff

// Structure to store IP address filter.
typedef struct _IPFILTERINFO {
    BYTE bIpAddrToBlock;
    ULONG uHexAddrToBlock;
    UINT64 u64VistaFilterId;
} IPFILTERINFO, * PIPFILTERINFO;

// List of filters.
typedef std::list<IPFILTERINFO> IPFILTERINFOLIST;

class PacketFilter
{
private:
    // Firewall engine handle.
    HANDLE m_hEngineHandle;

    // Firewall sublayer GUID.
    GUID m_subLayerGUID;

    // List of filters.
    IPFILTERINFOLIST m_lstFilters;

    // Method to create/delete packet filter interface.
    DWORD CreateDeleteInterface(bool bCreate);

    // Method to bind/unbind to/from packet filter interface.
    DWORD BindUnbindInterface(bool bBind);

    // Method to add/remove filter.
    DWORD AddRemoveFilter(bool bAdd);

public:

    // Constructor.
    PacketFilter();

    // Destructor.
    ~PacketFilter();

    // Method to add IP addresses to m_lstFilters list.
    void AddToBlockList(char* szIpAddrToBlock, ULONG hexAddr);

    BOOL BlockDomain(const char* domainName);

    // Method to start packet filter.
    BOOL StartFirewall();

    // Method to stop packet filter.
    BOOL StopFirewall();
};

#endif