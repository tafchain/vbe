template<typename MAP_TYPE, typename TYPE>
inline void CVbeService::InsertSession(MAP_TYPE& mapSession, TYPE* session, CMcpHandler* mcpHandle)
{
	session->m_pServiceHandler = (CVbeServiceHandler*)mcpHandle;
	session->m_pServiceHandler->m_arrUserSession.Insert(session);
	session->m_nSessionID = m_nSessionID;

	SetDscTimer(session, EN_SESSION_TIMEOUT_VALUE);

	mapSession.DirectInsert(m_nSessionID++, session);
}

template<typename MAP_TYPE>
inline CVbeService::IUserSession* CVbeService::EraseSession(MAP_TYPE& mapSession, ACE_UINT32 sessionID)
{
	auto pSession = mapSession.Erase(sessionID);

	if (pSession)
	{
		CancelDscTimer(pSession);
		pSession->m_pServiceHandler->m_arrUserSession.Erase(pSession);
		return pSession;
	}

	return nullptr;
}

template<typename RSP_TYPE, typename WRAPPER_TYPE>
inline ACE_INT32 CVbeService::EncryptSendResponse(RSP_TYPE& rsp, WRAPPER_TYPE& wrapper, const DSC::CDscShortBlob& envelopeKey, ACE_UINT32 nHandleID)
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
		rsp.m_data.Set(encryptBuf, encryptBufLen);

		DSC_RUN_LOG_FINE("m_data:%s", rsp.m_data.c_str());
		if (DSC_UNLIKELY(this->SendHtsMsg(rsp, nHandleID)))
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