#include "vbe_client_service.h"

template<typename MAP_TYPE, typename TYPE>
void CVbeClientService::InsertSession(MAP_TYPE&mapSession, TYPE* session)
{
	session->m_nCltSessionID = m_nSessionID;
	SetDscTimer(session, EN_SESSION_TIMEOUT_VALUE);
	mapSession.DirectInsert(m_nSessionID, session);
	++m_nSessionID;
}

template<typename MAP_TYPE>
inline CVbeClientService::IBaseSession* CVbeClientService::EraseSession(MAP_TYPE& mapSession, ACE_UINT32 nSessionID)
{
	auto pSession = mapSession.Erase(nSessionID);
	
	if (pSession)
	{
		this->CancelDscTimer(pSession);
	}

	return pSession;
	
}

template<typename REQ_TYPE, typename WRAPPER_TYPE>
inline ACE_INT32 CVbeClientService::EncryptSendRequest(REQ_TYPE& req, WRAPPER_TYPE& wrapper, const DSC::CDscShortBlob& envelopeKey, ACE_UINT32 nHandleID)
{
	ACE_INT32 nReturnCode = VBH::EN_OK_TYPE;
	char* encryptBuf = nullptr;
	ACE_UINT32 encryptBufLen = 0;

	if (VBE::EncryptWrapperMsg(wrapper, envelopeKey, encryptBuf, encryptBufLen))
	{
		nReturnCode = VBH::EN_ENCRYPT_ERROR_TYPE;
		DSC_RUN_LOG_ERROR("EncryptWrapperMsg error");
	}
	else
	{
		req.m_data.Set(encryptBuf, encryptBufLen);

		DSC_RUN_LOG_FINE("m_data:%s", req.m_data.c_str());
		if (DSC_UNLIKELY(this->SendHtsMsg(req, nHandleID)))
		{
			nReturnCode = VBH::EN_NETWORK_ERROR_TYPE;
			DSC_RUN_LOG_ERROR("SendHtsMsg error");
		}
		else
		{

		}
	}

	if (encryptBuf)
	{
		DSC_THREAD_SIZE_FREE(encryptBuf, encryptBufLen);
	}
	
	return nReturnCode;
}

