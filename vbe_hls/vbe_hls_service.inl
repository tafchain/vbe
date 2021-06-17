#include "vbe_hls_service.h"
template<typename MAP_TYPE, typename TYPE>
inline void CVbeHlsService::InsertSession(MAP_TYPE& mapSession, TYPE* session, const CDscMsg::CDscMsgAddr& mcpHandle)
{
	session->m_srcMsgAddr = mcpHandle;
	session->m_nHlsSessionID = m_nHlsSessionID;
	mapSession.DirectInsert(m_nHlsSessionID++, session);
}

template<typename MAP_TYPE>
inline CVbeHlsService::IHlsBaseSession* CVbeHlsService::EraseSession(MAP_TYPE& mapSession, ACE_UINT32 sessionID)
{
	return mapSession.Erase(sessionID);
}

template<typename MAP_TYPE>
inline CVbeHlsService::IHlsBaseSession* CVbeHlsService::EraseTimerSession(MAP_TYPE& mapSession, ACE_UINT32 sessionID)
{
	auto p = mapSession.Erase(sessionID);

	if (p)
	{
		CancelDscTimer(p);
	}

	return p;
}

template<typename MAP_TYPE>
inline CVbeHlsService::IHlsBaseSession* CVbeHlsService::FindSession(MAP_TYPE& mapSession, ACE_UINT32 sessionID)
{
	return mapSession.Find(sessionID);
}
