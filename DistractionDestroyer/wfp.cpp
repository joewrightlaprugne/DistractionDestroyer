#include "wfp.h"

/******************************************************************************
PacketFilter::PacketFilter() - Constructor
*******************************************************************************/
PacketFilter::PacketFilter()
{
    try
    {
        // Initialize member variables.
        m_hEngineHandle = NULL;
        ::ZeroMemory(&m_subLayerGUID, sizeof(GUID));
    }
    catch (...)
    {
    }
}

/******************************************************************************
PacketFilter::~PacketFilter() - Destructor
*******************************************************************************/
PacketFilter::~PacketFilter()
{
    try
    {
        // Stop firewall before closing.
        StopFirewall();
    }
    catch (...)
    {
    }
}

/******************************************************************************
PacketFilter::CreateDeleteInterface - This method creates or deletes a packet
                                      filter interface.
*******************************************************************************/
DWORD PacketFilter::CreateDeleteInterface(bool bCreate)
{
    DWORD dwFwAPiRetCode = ERROR_BAD_COMMAND;
    try
    {
        if (bCreate)
        {
            // Create packet filter interface.
            dwFwAPiRetCode = ::FwpmEngineOpen0(NULL,
                RPC_C_AUTHN_WINNT,
                NULL,
                NULL,
                &m_hEngineHandle);
        }
        else
        {
            if (NULL != m_hEngineHandle)
            {
                // Close packet filter interface.
                dwFwAPiRetCode = ::FwpmEngineClose0(m_hEngineHandle);
                m_hEngineHandle = NULL;
            }
        }
    }
    catch (...)
    {
    }
    return dwFwAPiRetCode;
}

/******************************************************************************
PacketFilter::BindUnbindInterface - This method binds to or unbinds from a
                                    packet filter interface.
*******************************************************************************/
DWORD PacketFilter::BindUnbindInterface(bool bBind)
{
    DWORD dwFwAPiRetCode = ERROR_BAD_COMMAND;
    try
    {
        if (bBind)
        {
            RPC_STATUS rpcStatus = { 0 };
            FWPM_SUBLAYER0 SubLayer = { 0 };

            // Create a GUID for our packet filter layer.
            rpcStatus = ::UuidCreate(&SubLayer.subLayerKey);
            if (NO_ERROR == rpcStatus)
            {
                // Save GUID.
                ::CopyMemory(&m_subLayerGUID,
                    &SubLayer.subLayerKey,
                    sizeof(SubLayer.subLayerKey));

                // Populate packet filter layer information.
                SubLayer.displayData.name = (wchar_t*)"MyVistaFirewall";
                SubLayer.displayData.description = (wchar_t*)"MyVistaFirewall";
                SubLayer.flags = 0;
                SubLayer.weight = 0x100;

                // Add packet filter to our interface.
                dwFwAPiRetCode = ::FwpmSubLayerAdd0(m_hEngineHandle,
                    &SubLayer,
                    NULL);
            }
        }
        else
        {
            // Delete packet filter layer from our interface.
            dwFwAPiRetCode = ::FwpmSubLayerDeleteByKey0(m_hEngineHandle,
                &m_subLayerGUID);
            ::ZeroMemory(&m_subLayerGUID, sizeof(GUID));
        }
    }
    catch (...)
    {
    }
    return dwFwAPiRetCode;
}

/******************************************************************************
PacketFilter::AddRemoveFilter - This method adds or removes a filter to an
                                existing interface.
*******************************************************************************/
DWORD PacketFilter::AddRemoveFilter(bool bAdd)
{
    DWORD dwFwAPiRetCode = ERROR_BAD_COMMAND;
    try
    {
        if (bAdd)
        {
            if (m_lstFilters.size())
            {
                IPFILTERINFOLIST::iterator itFilters;
                for (itFilters = m_lstFilters.begin(); itFilters != m_lstFilters.end(); itFilters++)
                {
                    if ((NULL != itFilters->bIpAddrToBlock) && (0 != itFilters->uHexAddrToBlock))
                    {
                        FWPM_FILTER0 Filter = { 0 };
                        FWPM_FILTER_CONDITION0 Condition = { 0 };
                        FWP_V4_ADDR_AND_MASK AddrMask = { 0 };

                        // Prepare filter condition.
                        Filter.subLayerKey = m_subLayerGUID;
                        Filter.displayData.name = (wchar_t*)FIREWALL_SERVICE_NAMEW;
                        Filter.layerKey = FWPM_LAYER_INBOUND_TRANSPORT_V4;
                        Filter.action.type = FWP_ACTION_BLOCK;
                        Filter.weight.type = FWP_EMPTY;
                        Filter.filterCondition = &Condition;
                        Filter.numFilterConditions = 1;

                        // Remote IP address should match itFilters->uHexAddrToBlock.
                        Condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                        Condition.matchType = FWP_MATCH_EQUAL;
                        Condition.conditionValue.type = FWP_V4_ADDR_MASK;
                        Condition.conditionValue.v4AddrMask = &AddrMask;


                        // Add IP address to be blocked.
                        AddrMask.addr = itFilters->uHexAddrToBlock;
                        AddrMask.mask = VISTA_SUBNET_MASK;

                        // Add filter condition to our interface. Save filter id in itFilters->u64VistaFilterId.
                        dwFwAPiRetCode = ::FwpmFilterAdd0(m_hEngineHandle,
                            &Filter,
                            NULL,
                            &(itFilters->u64VistaFilterId));
                    }
                }
            }
        }
        else
        {
            if (m_lstFilters.size())
            {
                IPFILTERINFOLIST::iterator itFilters;
                for (itFilters = m_lstFilters.begin(); itFilters != m_lstFilters.end(); itFilters++)
                {
                    if ((NULL != itFilters->bIpAddrToBlock) && (0 != itFilters->uHexAddrToBlock))
                    {
                        // Delete all previously added filters.
                        dwFwAPiRetCode = ::FwpmFilterDeleteById0(m_hEngineHandle,
                            itFilters->u64VistaFilterId);
                        itFilters->u64VistaFilterId = 0;
                    }
                }
            }
        }
    }
    catch (...)
    {
    }
    return dwFwAPiRetCode;
}

/******************************************************************************
PacketFilter::AddToBlockList - This public method allows caller to add
                               IP addresses which need to be blocked.
*******************************************************************************/
void PacketFilter::AddToBlockList(char* szIpAddrToBlock, ULONG hexAddr)
{
    IPFILTERINFO stIPFilter = { 0 };

    hexAddr = ntohl(hexAddr);

    IN_ADDR AddressStructure;
    inet_pton(AF_INET, szIpAddrToBlock, &AddressStructure);
    stIPFilter.uHexAddrToBlock = hexAddr;
    stIPFilter.bIpAddrToBlock = AddressStructure.s_addr;

    // Push the IP address information to list.
    m_lstFilters.push_back(stIPFilter);
}

/******************************************************************************
PacketFilter::StartFirewall - This public method starts firewall.
*******************************************************************************/
BOOL PacketFilter::StartFirewall()
{
    BOOL bStarted = FALSE;
    try
    {
        // Create packet filter interface.
        if (ERROR_SUCCESS == CreateDeleteInterface(true))
        {
            // Bind to packet filter interface.
            if (ERROR_SUCCESS == BindUnbindInterface(true))
            {
                // Add filters.
                AddRemoveFilter(true);

                bStarted = TRUE;
            }
        }
    }
    catch (...)
    {
    }
    return bStarted;
}

/******************************************************************************
PacketFilter::StopFirewall - This method stops firewall.
*******************************************************************************/
BOOL PacketFilter::StopFirewall()
{
    BOOL bStopped = FALSE;
    try
    {
        // Remove all filters.
        AddRemoveFilter(false);
        m_lstFilters.clear();

        // Unbind from packet filter interface.
        if (ERROR_SUCCESS == BindUnbindInterface(false))
        {
            // Delete packet filter interface.
            if (ERROR_SUCCESS == CreateDeleteInterface(false))
            {
                cout << "Stopped firewall" << endl;
                bStopped = TRUE;
            }
        }
    }
    catch (...)
    {
    }
    return bStopped;
}

/******************************************************************************
PacketFilter::BlockDomain - This method retrieves the various IP addresses associated with a domain and blocks them all.
*******************************************************************************/
BOOL PacketFilter::BlockDomain(const char* domainName)
{
    hostent* WSAAPI HostentStructure = gethostbyname(domainName);

    int LastError = WSAGetLastError();
    if (LastError)
    {
        return false;
    }
    int i = 0;
    in_addr AddressStructure;
    while (HostentStructure->h_addr_list[i] != 0) {
        u_long hexAddr = *(u_long*)HostentStructure->h_addr_list[i];
        AddressStructure.s_addr = hexAddr;
        AddToBlockList(inet_ntoa(AddressStructure), hexAddr);
        i++;
    }
    return true;
}