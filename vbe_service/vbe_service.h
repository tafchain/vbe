#ifndef _VBE_SERVICE_H_0951345980123479
#define _VBE_SERVICE_H_0951345980123479

#include "vbe/vbe_common/vbe_common_msg.h"
#include "vbe/vbe_common/vbe_hls_router.h"

#include "dsc/protocol/hts/dsc_hts_service.h"
#include "dsc/protocol/mcp/mcp_asynch_acceptor.h"
#include "dsc/container/bare_hash_map.h"
#include "dsc/protocol/mcp/mcp_server_handler.h"

class CVbhAgentService;
class PLUGIN_EXPORT CVbeService : public CDscHtsServerService
{
public:
	enum
	{
		EN_SERVICE_TYPE = VBE::EN_VBE_SERVICE_TYPE,

		EN_HASH_MAP_BITES = 16,
		EN_SESSION_TIMEOUT_VALUE = 60,
		EN_ONLINE_USER_TIMEOUT_VALUE = 600,
		EN_RETRY_TRANSFER_TIMEOUT_VALUE = 30,
	};

public:
	CVbeService(const CDscString& strIpAddr, const ACE_INT32 nPort);
	virtual ACE_INT32 OnInit(void) override;
	virtual ACE_INT32 OnExit(void) override;


public:
	void SetVbhAgentService(CVbhAgentService* pSrv);


protected:
	BEGIN_HTS_MESSAGE_BIND
	BIND_HTS_MESSAGE(VBE::CLoginCltVbeReq)
	BIND_HTS_MESSAGE(VBE::CTransferCltVbeReq)
	BIND_HTS_MESSAGE(VBE::CGetUserInfoCltVbeReq)
	END_HTS_MESSAGE_BIND

public:
	ACE_INT32  OnHtsMsg(VBE::CLoginCltVbeReq& rLoginReq, CMcpHandler* pMcpHandler);
	ACE_INT32  OnHtsMsg(VBE::CTransferCltVbeReq& rTransferReq, CMcpHandler* pMcpHandler);
	ACE_INT32  OnHtsMsg(VBE::CGetUserInfoCltVbeReq& rGetUserInfoReq, CMcpHandler* pMcpHandler);

protected:
	BEGIN_BIND_DSC_MESSAGE
		DSC_BIND_MESSAGE(VBE::CCheckUsersHlsVbeRsp)
		DSC_BIND_MESSAGE(VBE::CTransferHlsVbeRsp)
		END_BIND_DSC_MESSAGE

public:
	void OnDscMsg(VBE::CCheckUsersHlsVbeRsp& rCheckUserRsp, const CDscMsg::CDscMsgAddr& rSrcMsgAddr);
	void OnDscMsg(VBE::CTransferHlsVbeRsp& rTransferRsp, const CDscMsg::CDscMsgAddr& rSrcMsgAddr);


public: 
	// CALLBACK FROM HAS
	void OnQueryCryptUserKeyResponse(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, const DSC::CDscShortBlob& cryptUserKey);
	void OnQueryUserInfoResponse(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, const DSC::CDscShortBlob& userInfo);
	void OnQueryTransactionInfoResponse(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, const DSC::CDscBlob& tranInfo);

private:

	class COnlineUser : public CDscServiceTimerHandler
	{
	public:
		DSC::CDscShortBlob m_userKey; // vbh user key
		DSC::CDscShortBlob m_vbeUserKey; // vbe user Key
		DSC::CDscShortBlob m_cryptUserKey;
		ACE_UINT32 m_nToken;
		ACE_UINT32 m_nChannelID;

	public:
		virtual void OnTimer(void) override;

	public:
		ACE_UINT32 m_nKey = 0;
		COnlineUser* m_pPrev = NULL;
		COnlineUser* m_pNext = NULL;
	};

	class CVbeServiceHandler;
	class IUserSession : public CDscServiceTimerHandler
	{
	public:
		IUserSession(CVbeService& rService);
		IUserSession(const IUserSession&) = delete;
		IUserSession& operator= (const IUserSession&) = delete;
	public:
		virtual void OnNetError(void) = 0;

	public:
		ACE_UINT32 m_nSessionID;
		ACE_UINT32 m_nCltSessionID;
		CVbeServiceHandler* m_pServiceHandler;

	public:
		ACE_UINT32 m_nIndex = 0;

	protected:
		CVbeService& m_rService;
	};

	class CLoginSession : public IUserSession
	{
	public:
		CLoginSession(CVbeService& rService);
		~CLoginSession();
	public:
		virtual void OnTimer(void) override;
		virtual void OnNetError(void) override;

	public:
		DSC::CDscShortBlob m_nonce;
		DSC::CDscShortBlob m_userKey;
		DSC::CDscShortBlob m_vbeUserKey;
		ACE_UINT32 m_nChannelID;
	public:
		ACE_UINT32 m_nKey = 0;
		CLoginSession* m_pPrev = NULL;
		CLoginSession* m_pNext = NULL;
	};

	class CTransferSession : public IUserSession
	{
	public:
		CTransferSession(CVbeService& rService);
		~CTransferSession();
	public:
		virtual void OnTimer(void) override;
		virtual void OnNetError(void) override;

	public:
		struct CReceiverList
		{
			DSC::CDscShortList<DSC::CDscShortBlob> m_lstReceiver;
			bool m_bChecked;
			bool m_bSentCheck;
		};
	public:
		COnlineUser* m_pOnlineUser;
		DSC::CDscShortBlob m_nonce;
		DSC::CDscShortBlob m_propose;
		DSC::CDscShortBlob m_transKey;
		ACE_UINT32 m_nTotalCoin;
		dsc_unordered_map_type(ACE_UINT32, CReceiverList*) m_mapReceiverList; // channel id -> receiver list

	public:
		ACE_UINT32 m_nKey = 0;
		CTransferSession* m_pPrev = NULL;
		CTransferSession* m_pNext = NULL;
	};

	class CCheckUserSession : public IUserSession
	{
	public:
		CCheckUserSession(CVbeService& rService);
		~CCheckUserSession();
	public:
		virtual void OnTimer(void) override;
		virtual void OnNetError(void) override;

	public:
		CTransferSession* m_pTransferSession;
		ACE_UINT32 m_nChannelID;

	public:
		ACE_UINT32 m_nKey = 0;
		CCheckUserSession* m_pPrev = NULL;
		CCheckUserSession* m_pNext = NULL;
	};

	class CGetUserInfoSession : public IUserSession
	{
	public:
		CGetUserInfoSession(CVbeService& rService);
		~CGetUserInfoSession();
	public:
		virtual void OnTimer(void) override;
		virtual void OnNetError(void) override;

	public:
		DSC::CDscShortBlob m_nonce;
		COnlineUser* m_pOnlineUser;

	public:
		ACE_UINT32 m_nKey = 0;
		CGetUserInfoSession* m_pPrev = NULL;
		CGetUserInfoSession* m_pNext = NULL;
	};

private:
	class CVbeServiceHandler : public CMcpServerHandler
	{
	public:
		CVbeServiceHandler(CMcpServerService& rService, ACE_HANDLE handle, const ACE_INT32 nHandleID);

	public:
		CDscTypeArray<IUserSession> m_arrUserSession;
	};

private:
	void OnTimeOut(CLoginSession* pRegSession);
	void OnNetworkError(CLoginSession* pRegSession);

	void OnTimeOut(CCheckUserSession* pCheckUserSession);
	void OnNetworkError(CCheckUserSession* pCheckUserSession);

	void OnTimeOut(CTransferSession* pTransferSession);
	void OnNetworkError(CTransferSession* pTransferSession);

	void OnTimeOut(CGetUserInfoSession* pGetUserInfoSession);
	void OnNetworkError(CGetUserInfoSession* pGetUserInfoSession);

	void ResponseLogin(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, ACE_INT32 nHandleID);
	void ResponseLogin(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, ACE_INT32 nHandleID, const DSC::CDscShortBlob &envelopeKey,  DSC::CDscShortBlob &nonce,  ACE_UINT32 nToken);
	void ResponseTransfer(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, ACE_INT32 nHandleID);
	void ResponseTransfer(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, ACE_INT32 nHandleID, const DSC::CDscShortBlob& enveloperKey, DSC::CDscShortBlob& nonce, DSC::CDscShortBlob& transKey);
	void ResponseGetUserInfo(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, ACE_INT32 nHandleID);
	void ResponseGetUserInfo(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, ACE_INT32 nHandleID, const DSC::CDscShortBlob& enveloperKey, DSC::CDscShortBlob& nonce, DSC::CDscShortBlob& userinfo);

	template<typename MAP_TYPE, typename TYPE>
	void InsertSession(MAP_TYPE& mapSession, TYPE* session, CMcpHandler* mcpHandle);
	template<typename MAP_TYPE>
	IUserSession* EraseSession(MAP_TYPE& mapSession, ACE_UINT32 sessionID);
	template<typename RSP_TYPE, typename WRAPPER_TYPE>
	ACE_INT32 EncryptSendResponse(RSP_TYPE& req, WRAPPER_TYPE& wrapper, const DSC::CDscShortBlob& envelopeKey, ACE_UINT32 nHandleID);

	virtual CMcpServerHandler* AllocMcpHandler(ACE_HANDLE handle) override;

private:
	ACE_UINT32 NewToken();
	ACE_INT32 DoTransferPropose(CTransferSession* pTransferSession);
	void ReleaseTransferSession(CTransferSession* pTransferSession);

private:
	using online_user_session_map_type = CBareHashMap<ACE_UINT32, COnlineUser, EN_HASH_MAP_BITES>;

	using login_session_map_type = CBareHashMap<ACE_UINT32, CLoginSession, EN_HASH_MAP_BITES>;
	using transfer_session_map_type = CBareHashMap<ACE_UINT32, CTransferSession, EN_HASH_MAP_BITES>;
	using check_user_session_map_type = CBareHashMap<ACE_UINT32, CCheckUserSession, EN_HASH_MAP_BITES>;
	using get_userinfo_session_map_type = CBareHashMap<ACE_UINT32, CGetUserInfoSession, EN_HASH_MAP_BITES>;

private:
	online_user_session_map_type m_mapOnlineUsers;

	login_session_map_type m_mapLoginSession;
	check_user_session_map_type m_mapCheckUserSession;
	transfer_session_map_type m_mapTransferSession;
	get_userinfo_session_map_type m_mapGetUserInfoSession;

private:

	VBE::CVbeHlsRouter m_hlsRouter;

	ACE_UINT32 m_nTokenSeq = 0;
	ACE_UINT32 m_nSessionID = 0;
	CVbhAgentService* m_pHas = nullptr;
	const CDscString m_strIpAddr;
	const ACE_INT32 m_nPort;
	CMcpAsynchAcceptor<CVbeService>* m_pAcceptor = NULL;
};

#include "vbe/vbe_service/vbe_service.inl"




#endif // !_VBE_SERVICE_H_0951345980123479






