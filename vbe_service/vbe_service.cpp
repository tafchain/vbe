#include "vbe/vbe_service/vbe_service.h"
#include "vbe/vbe_common/vbe_common_msg.h"
#include "vbe/vbe_common/vbe_common_msg_wrapper.h"
#include "vbe/vbe_common/vbe_user_util.h"
#include "vbe/vbe_common/vbe_cc_action_msg.h"
#include "vbe/vbe_service/vbh_agent_service.h"

#include "openssl/rand.h"
#include "openssl/err.h"

#include "dsc/db/per/persistence.h"
#include "dsc/dsc_database_factory.h"


CVbeService::CVbeService(const CDscString& strIpAddr, const ACE_INT32 nPort)
	: m_strIpAddr(strIpAddr)
	, m_nPort(nPort)
{
}

ACE_INT32 CVbeService::OnInit(void)
{
	if (CDscHtsServerService::OnInit())
	{
		DSC_RUN_LOG_ERROR("bc endorser service init failed!");

		return -1;
	}

	if (m_hlsRouter.Open())
	{
		DSC_RUN_LOG_ERROR("hls service router init failed.");
		return -1;
	}

	m_pAcceptor = DSC_THREAD_TYPE_NEW(CMcpAsynchAcceptor<CVbeService>) CMcpAsynchAcceptor<CVbeService>(*this);
	if (m_pAcceptor->Open(m_nPort, m_strIpAddr.c_str()))
	{
		DSC_THREAD_TYPE_DEALLOCATE(m_pAcceptor);
		m_pAcceptor = NULL;
		DSC_RUN_LOG_ERROR("acceptor failed, ip addr:%s, port:%d", m_strIpAddr.c_str(), m_nPort);

		return -1;
	}
	else
	{
		this->RegistHandler(m_pAcceptor, ACE_Event_Handler::ACCEPT_MASK);
	}

	DSC_RUN_LOG_INFO("vbe service init succeed!");

	return 0;
}

ACE_INT32 CVbeService::OnExit(void)
{
	return 0;
}

void CVbeService::SetVbhAgentService(CVbhAgentService* pSrv)
{
	m_pHas = pSrv;
}


void CVbeService::OnQueryCryptUserKeyResponse(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, const DSC::CDscShortBlob& cryptUserKey)
{
	auto pLoginSession = (CLoginSession*)EraseSession(m_mapLoginSession, nRequestID);

	if (pLoginSession)
	{
		char* decryptBuf = nullptr;
		ACE_UINT32 token = 0;
		DSC::CDscShortBlob nonce;

		if (nReturnCode == VBH::EN_OK_TYPE)
		{
			VBE::CLoginCltVbeReqDataWrapper wrapper(nonce);

			decryptBuf = VBE::DecryptWrapperMsg(wrapper, cryptUserKey, pLoginSession->m_nonce.c_str(), pLoginSession->m_nonce.size());
			if (decryptBuf)
			{
				auto onlineSession = DSC_THREAD_TYPE_NEW(COnlineUser) COnlineUser;

				token = onlineSession->m_nToken = NewToken();
				onlineSession->m_nChannelID = pLoginSession->m_nChannelID;
				onlineSession->m_userKey.Clone(pLoginSession->m_userKey);
				onlineSession->m_vbeUserKey.Clone(pLoginSession->m_vbeUserKey);
				onlineSession->m_cryptUserKey.Clone(cryptUserKey);

				SetDscTimer(onlineSession, EN_ONLINE_USER_TIMEOUT_VALUE);
				m_mapOnlineUsers.Insert(onlineSession->m_nToken, onlineSession);
			}
			else
			{
				nReturnCode = VBE::EN_DECRYPT_ERROR_TYPE;
			}
			
		}
		ResponseLogin(nReturnCode, pLoginSession->m_nCltSessionID, pLoginSession->m_pServiceHandler->GetHandleID(), cryptUserKey, nonce, token);
		DSC_THREAD_TYPE_DELETE(pLoginSession);

		if (decryptBuf)
		{
			DSC_THREAD_FREE(decryptBuf);
		}
	}
}

void CVbeService::OnQueryUserInfoResponse(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, const DSC::CDscShortBlob& cuserInfo)
{
	auto pGetUserInfoSession = (CGetUserInfoSession*)EraseSession(m_mapGetUserInfoSession, nRequestID);

	if (pGetUserInfoSession)
	{
		DSC::CDscShortBlob userInfo;
		
		userInfo.Set(cuserInfo.GetBuffer(), cuserInfo.GetSize());

		ResponseGetUserInfo(nReturnCode, pGetUserInfoSession->m_nCltSessionID, pGetUserInfoSession->m_pServiceHandler->GetHandleID(), pGetUserInfoSession->m_pOnlineUser->m_cryptUserKey, pGetUserInfoSession->m_nonce, userInfo);
		DSC_THREAD_TYPE_DELETE(pGetUserInfoSession);
	}
}

void CVbeService::OnQueryTransactionInfoResponse(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, const DSC::CDscBlob& tranInfo)
{
}


void CVbeService::ResponseLogin(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, ACE_INT32 nHandleID)
{
	VBE::CLoginVbeCltRsp rsp;
	
	rsp.m_nReturnCode = nReturnCode;
	rsp.m_nSrcRequestID = nRequestID;

	this->SendHtsMsg(rsp, nHandleID);
}

void CVbeService::ResponseLogin(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, ACE_INT32 nHandleID,const DSC::CDscShortBlob& envelopeKey, DSC::CDscShortBlob& nonce, ACE_UINT32 nToken)
{
	VBE::CLoginVbeCltRsp rsp;
	VBE::CLoginVbeCltRspDataWrapper wrapper(nonce, nToken);

	rsp.m_nReturnCode = nReturnCode;
	rsp.m_nSrcRequestID = nRequestID;

	EncryptSendResponse(rsp, wrapper, envelopeKey, nHandleID);
}

void CVbeService::ResponseTransfer(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, ACE_INT32 nHandleID)
{
	VBE::CTransferVbeCltRsp rsp;

	rsp.m_nReturnCode = nReturnCode;
	rsp.m_nSrcRequestID = nRequestID;

	this->SendHtsMsg(rsp, nHandleID);
}

void CVbeService::ResponseTransfer(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, ACE_INT32 nHandleID, const DSC::CDscShortBlob& enveloperKey, DSC::CDscShortBlob& nonce, DSC::CDscShortBlob& transKey)
{
	VBE::CTransferVbeCltRsp rsp;
	VBE::CTransferVbeCltRspDataWrapper wrapper(nonce, transKey);

	rsp.m_nReturnCode = nReturnCode;
	rsp.m_nSrcRequestID = nRequestID;

	EncryptSendResponse(rsp, wrapper, enveloperKey, nHandleID);
}

void CVbeService::ResponseGetUserInfo(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, ACE_INT32 nHandleID)
{
	VBE::CGetUserInfoVbeCltRsp rsp;

	rsp.m_nReturnCode = nReturnCode;
	rsp.m_nSrcRequestID = nRequestID;

	this->SendHtsMsg(rsp, nHandleID);
}

void CVbeService::ResponseGetUserInfo(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, ACE_INT32 nHandleID, const DSC::CDscShortBlob& enveloperKey, DSC::CDscShortBlob& nonce, DSC::CDscShortBlob& userinfo)
{
	VBE::CGetUserInfoVbeCltRsp rsp;
	VBE::CGetUserInfoVbeCltRspDataWrapper wrapper(nonce, userinfo);

	rsp.m_nReturnCode = nReturnCode;
	rsp.m_nSrcRequestID = nRequestID;

	EncryptSendResponse(rsp, wrapper, enveloperKey, nHandleID);

}

CMcpServerHandler* CVbeService::AllocMcpHandler(ACE_HANDLE handle)
{
	return DSC_THREAD_DYNAMIC_TYPE_NEW(CVbeServiceHandler) CVbeServiceHandler(*this, handle, this->AllocHandleID());
}

ACE_UINT32 CVbeService::NewToken()
{
	while (true)
	{
		if (m_mapOnlineUsers.Find(m_nTokenSeq) == nullptr)
		{
			return m_nTokenSeq++;
		}
		m_nTokenSeq++;
	}
	return 0;
}

ACE_INT32 CVbeService::DoTransferPropose(CTransferSession* pTransferSession)
{
	CDscMsg::CDscMsgAddr addr;

	// 锁定用户已查找过hls，这里一定可以找到
	if (m_hlsRouter.GetHlsAddr(addr, pTransferSession->m_pOnlineUser->m_nChannelID))
	{
		DSC_RUN_LOG_ERROR("Not Fount User Channel %u", pTransferSession->m_pOnlineUser->m_nChannelID);
		return VBE::EN_SYSTEM_ERROR_TYPE;
	}

	VBE::CTransferVbeHlsReq req;

	req.m_bMain = true;
	req.m_nSrcRequestID = m_nSessionID;
	req.m_propose = pTransferSession->m_propose;
	req.m_sponsorUserKey = pTransferSession->m_pOnlineUser->m_userKey;

	if (SendDscMessage(req, addr))
	{
		return VBE::EN_NETWORK_ERROR_TYPE;
	}

	pTransferSession->m_nSessionID = m_nSessionID;

	SetDscTimer(pTransferSession, EN_SESSION_TIMEOUT_VALUE);

	m_mapTransferSession.DirectInsert(m_nSessionID++, pTransferSession);
	
	return 0;
}


void CVbeService::ReleaseTransferSession(CTransferSession* pTransferSession)
{
	DSC_THREAD_TYPE_DELETE(pTransferSession);
}


ACE_INT32 CVbeService::OnHtsMsg(VBE::CLoginCltVbeReq& rReq, CMcpHandler* pMcpHandler)
{
	DSC_RUN_LOG_FINE("CLoginCltVbeReq %s", rReq.m_data.c_str());

	DSC::CDscShortBlob vbhUserKey;
	ACE_UINT32 nChannelID;

	if (VBE::CVbeUserUtil::DecodeVbeUserKey(vbhUserKey, nChannelID, rReq.m_userKey))
	{
		return -1;
	}
	// TODO QueryCryptUserKey
	auto nReturnCode = m_pHas->QueryUserInfo(m_nSessionID, nChannelID, vbhUserKey);

	if (nReturnCode)
	{
		DSC_RUN_LOG_ERROR("QueryUserInfo failed.");
	}
	else
	{
		auto pSession = DSC_THREAD_TYPE_NEW(CLoginSession) CLoginSession(*this);

		pSession->m_nonce.Clone(rReq.m_data); // 等待解密
		pSession->m_nCltSessionID = rReq.m_nSrcRequestID;
		pSession->m_userKey.Clone(vbhUserKey);
		pSession->m_vbeUserKey.Clone(rReq.m_userKey);
		pSession->m_nChannelID = nChannelID;
		InsertSession(m_mapLoginSession, pSession, pMcpHandler);
	}
	DSC_RUN_LOG_FINE("CLoginCltVbeReq out", rReq.m_data.c_str());
	return 0;
}


ACE_INT32 CVbeService::OnHtsMsg(VBE::CTransferCltVbeReq& rTransferReq, CMcpHandler* pMcpHandler)
{
	auto pOnlineUser = m_mapOnlineUsers.Find(rTransferReq.m_nToken);

	if (!pOnlineUser)
	{
		ResponseTransfer(VBE::EN_USER_NOT_LOGIN_ERROR_TYPE, rTransferReq.m_nSrcRequestID, pMcpHandler->GetHandleID());

		return 0;
	}
	
	DSC::CDscShortBlob nonce;
	ACE_UINT32 nTotalCoin;
	DSC::CDscShortList<DSC::CDscShortBlob> userKeyList;
	DSC::CDscShortList<ACE_UINT32> coinList;
	VBE::CTransferCltVbeReqDataWrapper wrapper(nonce, nTotalCoin, userKeyList, coinList);
	char* decryptBuf = VBE::DecryptWrapperMsg(wrapper, pOnlineUser->m_cryptUserKey, rTransferReq.m_data.c_str(), rTransferReq.m_data.size());

	if (!decryptBuf)
	{
		ResponseTransfer(VBE::EN_DECRYPT_ERROR_TYPE, rTransferReq.m_nSrcRequestID, pMcpHandler->GetHandleID());

		return 0;
	}

	if (coinList.size() != userKeyList.size() || coinList.size() == 0)
	{
		ResponseTransfer(VBE::EN_PARAM_ERROR_TYPE, rTransferReq.m_nSrcRequestID, pMcpHandler->GetHandleID());

		return 0;
	}

	// 先把接收方按channel分组
	auto pTransferSession = DSC_THREAD_TYPE_NEW(CTransferSession) CTransferSession(*this);
	auto coinIt = coinList.begin();

	pTransferSession->m_nTotalCoin = 0;
	for (auto& userKey : userKeyList)
	{
		DSC::CDscShortBlob vbhUserKey;
		ACE_UINT32 nChannelID;

		if (VBE::CVbeUserUtil::DecodeVbeUserKey(vbhUserKey, nChannelID, userKey))
		{
			ResponseTransfer(VBE::EN_PARAM_ERROR_TYPE, rTransferReq.m_nSrcRequestID, pMcpHandler->GetHandleID());
			DSC_THREAD_TYPE_DELETE(pTransferSession);

			return 0;
		}

		auto receiverListIt = pTransferSession->m_mapReceiverList.find(nChannelID);
		CTransferSession::CReceiverList* receiverList;

		if (receiverListIt == pTransferSession->m_mapReceiverList.end())
		{
			receiverList = DSC_THREAD_TYPE_NEW(CTransferSession::CReceiverList) CTransferSession::CReceiverList;
			receiverList->m_bChecked = false;
			receiverList->m_bSentCheck = false;
			pTransferSession->m_mapReceiverList[nChannelID] = receiverList;
		}
		else
		{
			receiverList = receiverListIt->second;
		}

		DSC::CDscShortBlob tmpUserKey;

		tmpUserKey.Clone(vbhUserKey);

		receiverList->m_lstReceiver.push_back(tmpUserKey);
		pTransferSession->m_nTotalCoin += *coinIt;
		coinIt++;
	}

	if (pTransferSession->m_nTotalCoin != nTotalCoin)
	{
		DSC_THREAD_TYPE_DELETE(pTransferSession);
		ResponseTransfer(VBE::EN_PARAM_ERROR_TYPE, rTransferReq.m_nSrcRequestID, pMcpHandler->GetHandleID());

		return 0;
	}
	///把发起者放到receiver 中，方便查询
	auto receiverListIt = pTransferSession->m_mapReceiverList.find(pOnlineUser->m_nChannelID);
	CTransferSession::CReceiverList* receiverList;

	if (receiverListIt == pTransferSession->m_mapReceiverList.end())
	{
		receiverList = DSC_THREAD_TYPE_NEW(CTransferSession::CReceiverList) CTransferSession::CReceiverList;
		receiverList->m_bChecked = false;
		receiverList->m_bSentCheck = false;
		pTransferSession->m_mapReceiverList[pOnlineUser->m_nChannelID] = receiverList;
	}
	else
	{
		receiverList = receiverListIt->second;
	}

	DSC::CDscShortBlob tmpUserKey;

	tmpUserKey.Clone(pOnlineUser->m_userKey);

	receiverList->m_lstReceiver.push_back(tmpUserKey);

	/// 
	pTransferSession->m_nonce.Clone(nonce);
	pTransferSession->m_pOnlineUser = pOnlineUser;
	this->ResetDscTimer(pOnlineUser, EN_ONLINE_USER_TIMEOUT_VALUE);

// 组装propose
	VBE::CVbeCcActionTransferMsg msg;

	msg.m_nTotalCoin = nTotalCoin;
	msg.m_sponsorUserKey = pTransferSession->m_pOnlineUser->m_vbeUserKey;
	msg.m_lstUserKey = userKeyList;
	msg.m_lstCoin = coinList;

	char* proposeBuf = nullptr;
	size_t proposeBufLen = 0;

	DSC::Encode(msg, proposeBuf, proposeBufLen);
	pTransferSession->m_propose.Set(proposeBuf, proposeBufLen);

	if (pTransferSession->m_mapReceiverList.size() == 1)
	{
		// channel 内交易，直接提案
		DoTransferPropose(pTransferSession);
	}
	else
	{
		// channel 间交易， 先查用户是否有效
		for (auto it = pTransferSession->m_mapReceiverList.begin(); it != pTransferSession->m_mapReceiverList.end(); it++)
		{
			VBE::CCheckUsersVbeHlsReq req;

			req.m_nSrcRequestID = m_nSessionID;

			for (auto& receiver : it->second->m_lstReceiver)
			{
				req.m_lstUserKey.push_back(receiver);
			}

			CDscMsg::CDscMsgAddr addr;

			if (m_hlsRouter.GetHlsAddr(addr, it->first))
			{
				ReleaseTransferSession(pTransferSession);
				ResponseTransfer(VBE::EN_SYSTEM_ERROR_TYPE, rTransferReq.m_nSrcRequestID, pMcpHandler->GetHandleID());

				return 0;
			}

			if (SendDscMessage(req, addr))
			{
				ReleaseTransferSession(pTransferSession);
				ResponseTransfer(VBE::EN_NETWORK_ERROR_TYPE, rTransferReq.m_nSrcRequestID, pMcpHandler->GetHandleID());

				return 0;
			}

			it->second->m_bSentCheck = true;

			auto pCheckSession = DSC_THREAD_TYPE_NEW(CCheckUserSession) CCheckUserSession(*this);

			pCheckSession->m_pTransferSession = pTransferSession;
			pCheckSession->m_nChannelID = it->first;

			InsertSession(m_mapCheckUserSession, pCheckSession, pMcpHandler);
		}
	}

	pTransferSession->m_pServiceHandler = (CVbeServiceHandler*)pMcpHandler;
	pTransferSession->m_pServiceHandler->m_arrUserSession.Insert(pTransferSession);

	DSC_THREAD_FREE(decryptBuf);

	return 0;
}

ACE_INT32 CVbeService::OnHtsMsg(VBE::CGetUserInfoCltVbeReq& rGetUserInfoReq, CMcpHandler* pMcpHandler)
{
	auto pOnlineUser = m_mapOnlineUsers.Find(rGetUserInfoReq.m_nToken);
	ACE_INT32 nReturnCode = VBE::EN_OK_TYPE;

	if (pOnlineUser)
	{
		nReturnCode = m_pHas->QueryUserInfo(m_nSessionID, pOnlineUser->m_nChannelID, pOnlineUser->m_userKey);

		if (nReturnCode == VBE::EN_OK_TYPE)
		{
			DSC::CDscShortBlob nonce;
			VBE::CGetUserInfoCltVbeReqDataWrapper wrapper(nonce);
			char* decryptBuf = DecryptWrapperMsg(wrapper, pOnlineUser->m_cryptUserKey, rGetUserInfoReq.m_data.c_str(), rGetUserInfoReq.m_data.size());

			if (decryptBuf)
			{
				auto pGetUserInfoSession = DSC_THREAD_TYPE_NEW(CGetUserInfoSession) CGetUserInfoSession(*this);

				pGetUserInfoSession->m_nonce.Clone(nonce);
				pGetUserInfoSession->m_pOnlineUser = pOnlineUser;
				pGetUserInfoSession->m_nCltSessionID = rGetUserInfoReq.m_nSrcRequestID;
				InsertSession(m_mapGetUserInfoSession, pGetUserInfoSession, pMcpHandler);

				DSC_THREAD_FREE(decryptBuf);
			}
			else
			{
				nReturnCode = VBE::EN_DECRYPT_ERROR_TYPE;
			}
		}
	}
	else
	{
		nReturnCode = VBE::EN_USER_NOT_LOGIN_ERROR_TYPE;
	}
	
	return 0;
}

void CVbeService::OnDscMsg(VBE::CCheckUsersHlsVbeRsp& rCheckUserRsp, const CDscMsg::CDscMsgAddr& rSrcMsgAddr)
{
	auto pCheckUserSession = (CCheckUserSession*)EraseSession(m_mapCheckUserSession, rCheckUserRsp.m_nSrcRequestID);

	if (pCheckUserSession)
	{
		if (rCheckUserRsp.m_nReturnCode)
		{
			ResponseTransfer(rCheckUserRsp.m_nReturnCode, pCheckUserSession->m_pTransferSession->m_nCltSessionID, pCheckUserSession->m_pTransferSession->m_pServiceHandler->GetHandleID());
			ReleaseTransferSession(pCheckUserSession->m_pTransferSession);
		}
		else
		{
			ACE_UINT32 checkedCount = 0;

			for (auto& it : pCheckUserSession->m_pTransferSession->m_mapReceiverList)
			{
				if (it.first == pCheckUserSession->m_nChannelID)
				{
					it.second->m_bChecked = true;
				}

				if (it.second->m_bChecked)
				{
					checkedCount++;
				}
			}

			if (checkedCount == pCheckUserSession->m_pTransferSession->m_mapReceiverList.size())
			{
				DoTransferPropose(pCheckUserSession->m_pTransferSession);
			}
		}

		DSC_THREAD_TYPE_DELETE(pCheckUserSession);
	}
}

void CVbeService::OnDscMsg(VBE::CTransferHlsVbeRsp& rTransferRsp, const CDscMsg::CDscMsgAddr& rSrcMsgAddr)
{
	auto pTransferSession = m_mapTransferSession.Find(rTransferRsp.m_nSrcRequestID);

	if (pTransferSession)
	{
		if (rTransferRsp.m_nReturnCode)
		{
			ResponseTransfer(rTransferRsp.m_nReturnCode, rTransferRsp.m_nSrcRequestID, pTransferSession->m_pServiceHandler->GetHandleID());
		}
		else
		{
			ResponseTransfer(rTransferRsp.m_nReturnCode, rTransferRsp.m_nSrcRequestID, pTransferSession->m_pServiceHandler->GetHandleID(), pTransferSession->m_pOnlineUser->m_cryptUserKey, pTransferSession->m_nonce, rTransferRsp.m_transKey);
			ReleaseTransferSession(pTransferSession);
		}
	}
}

void CVbeService::COnlineUser::OnTimer()
{
	// TODO 
}
 
CVbeService::IUserSession::IUserSession(CVbeService& rService)
	:m_rService(rService)
{
}
CVbeService::CLoginSession::CLoginSession(CVbeService& rService)
	: IUserSession(rService)
{
}

CVbeService::CLoginSession::~CLoginSession()
{
	m_nonce.FreeBuffer();
	m_userKey.FreeBuffer();
	m_vbeUserKey.FreeBuffer();
}

void CVbeService::CLoginSession::OnTimer()
{
	m_rService.OnTimeOut(this);
}

void CVbeService::CLoginSession::OnNetError()
{
	m_rService.OnNetworkError(this);
}

CVbeService::CTransferSession::CTransferSession(CVbeService& rService)
	:IUserSession(rService)
{
}

CVbeService::CTransferSession::~CTransferSession()
{
	// TODO
}

void CVbeService::CTransferSession::OnTimer()
{
	m_rService.OnTimeOut(this);
}

void CVbeService::CTransferSession::OnNetError()
{
	m_rService.OnNetworkError(this);
}


CVbeService::CVbeServiceHandler::CVbeServiceHandler(CMcpServerService& rService, ACE_HANDLE handle, const ACE_INT32 nHandleID)
	:CMcpServerHandler(rService, handle, nHandleID)
{
}

CVbeService::CGetUserInfoSession::CGetUserInfoSession(CVbeService& rService)
	: IUserSession(rService)
{
}

CVbeService::CGetUserInfoSession::~CGetUserInfoSession()
{
	m_nonce.FreeBuffer();
}

void CVbeService::CGetUserInfoSession::OnTimer(void)
{
	m_rService.OnTimeOut(this);
}

void CVbeService::CGetUserInfoSession::OnNetError(void)
{
	m_rService.OnNetworkError(this);
}

void CVbeService::OnTimeOut(CVbeService::CLoginSession* pRegSession)
{
	ResponseLogin(VBE::EN_TIMEOUT_ERROR_TYPE, pRegSession->m_nCltSessionID, pRegSession->m_pServiceHandler->GetHandleID());
	EraseSession(m_mapLoginSession, pRegSession->m_nSessionID);
	DSC_THREAD_TYPE_DELETE(pRegSession);
}

void CVbeService::OnNetworkError(CVbeService::CLoginSession* pRegSession)
{
	EraseSession(m_mapLoginSession, pRegSession->m_nSessionID);
	DSC_THREAD_TYPE_DELETE(pRegSession);
}

void CVbeService::OnTimeOut(CCheckUserSession* pCheckUserSession)
{
}

void CVbeService::OnNetworkError(CCheckUserSession* pCheckUserSession)
{
}

void CVbeService::OnTimeOut(CVbeService::CTransferSession* pTransferSession)
{
	ResponseTransfer(VBE::EN_TIMEOUT_ERROR_TYPE, pTransferSession->m_nCltSessionID, pTransferSession->m_pServiceHandler->GetHandleID());
	EraseSession(m_mapTransferSession, pTransferSession->m_nSessionID);
	DSC_THREAD_TYPE_DELETE(pTransferSession);
}

void CVbeService::OnNetworkError(CVbeService::CTransferSession* pTransferSession)
{
	EraseSession(m_mapTransferSession, pTransferSession->m_nSessionID);
	DSC_THREAD_TYPE_DELETE(pTransferSession);
}

void CVbeService::OnTimeOut(CGetUserInfoSession* pGetUserInfoSession)
{
	ResponseGetUserInfo(VBE::EN_TIMEOUT_ERROR_TYPE, pGetUserInfoSession->m_nCltSessionID, pGetUserInfoSession->m_pServiceHandler->GetHandleID());
	EraseSession(m_mapGetUserInfoSession, pGetUserInfoSession->m_nSessionID);
	DSC_THREAD_TYPE_DELETE(pGetUserInfoSession);
}

void CVbeService::OnNetworkError(CGetUserInfoSession* pGetUserInfoSession)
{
	EraseSession(m_mapGetUserInfoSession, pGetUserInfoSession->m_nSessionID);
	DSC_THREAD_TYPE_DELETE(pGetUserInfoSession);
}

CVbeService::CCheckUserSession::CCheckUserSession(CVbeService& rService)
	:IUserSession(rService)
{
}

CVbeService::CCheckUserSession::~CCheckUserSession()
{
}

void CVbeService::CCheckUserSession::OnTimer(void)
{
	m_rService.OnTimeOut(this);
}

void CVbeService::CCheckUserSession::OnNetError(void)
{
	m_rService.OnNetworkError(this);
}
