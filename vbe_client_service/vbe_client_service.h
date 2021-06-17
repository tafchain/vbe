#ifndef VBE_CLIENT_SERVICE_H_275873835682456
#define VBE_CLIENT_SERVICE_H_275873835682456


#include "vbe/vbe_common/vbe_common_msg.h"
#include "vbe/vbe_common/vbe_common_def.h"

#include "vbe/vbe_client_sdk/vbe_client_sdk.h"

#include "vbh/common/vbh_encrypt_lib.h"

#include "openssl/ec.h"

#include "dsc/protocol/hts/dsc_hts_service.h"
#include "dsc/service_timer/dsc_service_timer_handler.h"
#include "dsc/container/bare_hash_map.h"

class PLUGIN_EXPORT CVbeClientService : public CDscHtsClientService
{
public:
	enum
	{
		EN_SERVICE_TYPE = VBE::EN_VBE_CLIENT_SERVICE_TYPE
	};

public:
	ACE_INT32 OnInit(void);
	ACE_INT32 OnExit(void);
protected:
	BEGIN_HTS_MESSAGE_BIND
		BIND_HTS_MESSAGE(VBE::CRegisterUserRegCltRsp)
		BIND_HTS_MESSAGE(VBE::CLoginVbeCltRsp)
		BIND_HTS_MESSAGE(VBE::CTransferVbeCltRsp)
		BIND_HTS_MESSAGE(VBE::CGetUserInfoVbeCltRsp)
		END_HTS_MESSAGE_BIND

public:
	ACE_INT32 OnHtsMsg(VBE::CRegisterUserRegCltRsp& rRegistUserRsp, CMcpHandler* pMcpHandler);
	ACE_INT32 OnHtsMsg(VBE::CLoginVbeCltRsp& rLoginRsp, CMcpHandler* pMcpHandler);
	ACE_INT32 OnHtsMsg(VBE::CTransferVbeCltRsp& rTransferRsp, CMcpHandler* pMcpHandler);
	ACE_INT32 OnHtsMsg(VBE::CGetUserInfoVbeCltRsp& rGetUserInfoRsp, CMcpHandler* pMcpHandler);

protected:
	BEGIN_BIND_DSC_MESSAGE
		DSC_BIND_MESSAGE(VBE::CInitSdk)
		DSC_BIND_MESSAGE(VBE::CRegisterUserApiCltReq)
		DSC_BIND_MESSAGE(VBE::CLoginApiCltReq)
		DSC_BIND_MESSAGE(VBE::CTransferApiCltReq)
		DSC_BIND_MESSAGE(VBE::CGetUserInfoApiCltReq)
		END_BIND_DSC_MESSAGE

public:
	void OnDscMsg(VBE::CInitSdk& rInitSdk, const CDscMsg::CDscMsgAddr& rSrcMsgAddr);
	void OnDscMsg(VBE::CRegisterUserApiCltReq& rRegistUserReq, const CDscMsg::CDscMsgAddr& rSrcMsgAddr);
	void OnDscMsg(VBE::CLoginApiCltReq& rLoginReq, const CDscMsg::CDscMsgAddr& rSrcMsgAddr);
	void OnDscMsg(VBE::CTransferApiCltReq& rTransferReq, const CDscMsg::CDscMsgAddr& rSrcMsgAddr);
	void OnDscMsg(VBE::CGetUserInfoApiCltReq& rGetUserInfoReq, const CDscMsg::CDscMsgAddr& rSrcMsgAddr);

	virtual ACE_INT32 OnConnectedNodify(CMcpClientHandler* pMcpClientHandler) override;
	virtual void OnNetworkError(CMcpHandler* pMcpHandler) override;
	ACE_INT32 OnConnectFailedNodify(PROT_COMM::CDscIpAddr& remoteAddr, const ACE_UINT32 nHandleID) override;

private:
	class CVbePeer
	{
	public:
		CDscString m_strIpAddr;
		ACE_INT32 m_nPort = 0;
		ACE_UINT32 m_nHandleID = 0;
		bool m_bConnected = false;
		DSC::CDscShortVector <ACE_UINT32> m_channels;
	public:
		ACE_UINT32 m_nKey = 0;
		CVbePeer* m_pPrev = NULL;
		CVbePeer* m_pNext = NULL;
	};
	
	class COnlineUser;

	//通用基础session 
	class IBaseSession : public CDscServiceTimerHandler
	{
	public:
		IBaseSession(CVbeClientService& rRegistUserService);

	public:
		virtual void OnNetError(void) = 0; //网络出错时，释放本session的函数

	public:
		ACE_UINT32 m_nCltSessionID; //客户端sessionID
		ACE_UINT32 m_nSrcSessionID; //发送业务请求方的sessionID

	public:
		ACE_UINT32 m_nIndex = 0; //使用 CDscTypeArray 容器必须具备的接口

	protected:
		CVbeClientService& m_rClientBaseService;
	};

	class CHandleSession  //管理通信句柄的session
	{
	public:
		CDscTypeArray<IBaseSession> m_arrSession;
		CMcpHandler* m_pMcpHandler = NULL;

	public:
		ACE_UINT32 m_nIndex = 0; //使用 CDscTypeArray 容器必须具备的接口

	public:
		ACE_UINT32 m_nKey = 0;
		CHandleSession* m_pPrev = NULL;
		CHandleSession* m_pNext = NULL;
	};

	//注册用户的session
	class CRegisterUserSession : public IBaseSession
	{
	public:
		CRegisterUserSession(CVbeClientService& rClientBaseService);
		~CRegisterUserSession();

	public:
		virtual void OnTimer(void) override;
		virtual void OnNetError(void) override;

	public:
		bool m_waitingSend;
		DSC::CDscShortBlob m_nonce;
		DSC::CDscShortBlob m_userInfo;
		DSC::CDscShortBlob m_serverCryptKey;

	public:
		ACE_UINT32 m_nKey = 0;//hash map用到
		CRegisterUserSession* m_pPrev = NULL;//hash map用到
		CRegisterUserSession* m_pNext = NULL;//hash map用到

	};

	class CLoginSession : public IBaseSession
	{
	public:
		CLoginSession(CVbeClientService& rClientBaseService);
		~CLoginSession();

	public:
		virtual void OnTimer(void) override;
		virtual void OnNetError(void) override;

	public:
		bool m_waitingSend;
		DSC::CDscShortBlob m_nonce;
		DSC::CDscShortBlob m_userKey;
		DSC::CDscShortBlob m_cryptUserKey;
		CVbePeer* m_VbeServer = nullptr;

	public:
		ACE_UINT32 m_nKey = 0;//hash map用到
		CLoginSession* m_pPrev = NULL;//hash map用到
		CLoginSession* m_pNext = NULL;//hash map用到

	};

	class CTransferSession : public IBaseSession
	{
	public:
		CTransferSession(CVbeClientService& rClientBaseService);
		~CTransferSession();

	public:
		virtual void OnTimer(void) override;
		virtual void OnNetError(void) override;

	public:
		DSC::CDscShortBlob m_nonce;
		COnlineUser* m_pOnlineUser;

	public:
		ACE_UINT32 m_nKey = 0;//hash map用到
		CTransferSession* m_pPrev = NULL;//hash map用到
		CTransferSession* m_pNext = NULL;//hash map用到

	};

	class CGetUserInfoSession : public IBaseSession
	{
	public:
		CGetUserInfoSession(CVbeClientService& rClientBaseService);
		~CGetUserInfoSession();

	public:
		virtual void OnTimer(void) override;
		virtual void OnNetError(void) override;

	public:
		
		DSC::CDscShortBlob m_nonce;
		COnlineUser* m_pOnlineUser;
	public:
		ACE_UINT32 m_nKey = 0;//hash map用到
		CGetUserInfoSession* m_pPrev = NULL;//hash map用到
		CGetUserInfoSession* m_pNext = NULL;//hash map用到
	};

	class COnlineUser
	{
	public:
		COnlineUser(CVbeClientService& srv);
		~COnlineUser();
	public:
		DSC::CDscShortBlob m_userKey;
		DSC::CDscShortBlob m_cryptUserKey;
		ACE_UINT32 m_nToken;
		ACE_UINT32 m_nVbeToken;
		CVbePeer* m_VbeServer = nullptr;

	public:
		CVbeClientService& m_clientService;
	public:
		ACE_UINT32 m_nKey = 0;
		COnlineUser* m_pPrev = NULL;
		COnlineUser* m_pNext = NULL;
	};

private:
	enum
	{
		EN_HASH_MAP_BITES = 16,
		EN_SESSION_TIMEOUT_VALUE = 60,
		EN_ONLINE_USER_TIMEOUT_VALUE = 600,
	};


public:
	void OnTimeOut(CRegisterUserSession* pRegistUserSession);
	void OnNetError(CRegisterUserSession* pRegistUserSession);

	void OnTimeOut(CLoginSession* pLoginSession);
	void OnNetError(CLoginSession* pLoginSession);

	void OnTimeOut(CTransferSession* pTransferSession);
	void OnNetError(CTransferSession* pTransferSession);

	void OnTimeOut(CGetUserInfoSession* pGetUserInfoSession);
	void OnNetError(CGetUserInfoSession* pGetUserInfoSession);


private:
	using register_user_session_map_type = CBareHashMap<ACE_UINT32, CRegisterUserSession, EN_HASH_MAP_BITES>;
	using login_session_map_type = CBareHashMap<ACE_UINT32, CLoginSession, EN_HASH_MAP_BITES>;
	using transfer_session_map_type = CBareHashMap<ACE_UINT32, CTransferSession, EN_HASH_MAP_BITES>;
	using get_userinfo_session_map_type = CBareHashMap<ACE_UINT32, CGetUserInfoSession, EN_HASH_MAP_BITES>;

	using vbe_peer_map_type = CBareHashMap<ACE_UINT32, CVbePeer, EN_HASH_MAP_BITES>; // channelID -> vbe peer
	using online_user_session_map_type = CBareHashMap<ACE_UINT32, COnlineUser, EN_HASH_MAP_BITES>;  // token -> loginuser


private:

	void OnRegisterUserResponse(ACE_INT32 nReturnCode,  ACE_UINT32 nRequestID, DSC::CDscShortBlob *userKey = nullptr);
	void OnLoginResponse(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, ACE_UINT32 token = 0);
	void OnTransferResponse(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, DSC::CDscShortBlob* transKey = nullptr);
	void OnGetUserInfoResponse(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, DSC::CDscShortBlob* userinfo = nullptr);

	ACE_INT32 SendRequest(CRegisterUserSession* pSession);
	ACE_INT32 SendRequest(CLoginSession* pSession);
	ACE_INT32 SendRequest(CTransferSession* pSession);

	void MakeNonce(DSC::CDscShortBlob& rNonce);
	ACE_UINT32 NewToken();

	template<typename MAP_TYPE, typename TYPE>
	void InsertSession(MAP_TYPE& mapSession, TYPE* session);

	template<typename MAP_TYPE>
	IBaseSession* EraseSession(MAP_TYPE& mapSession, ACE_UINT32 nSessionID);
	template<typename REQ_TYPE, typename WRAPPER_TYPE>
	ACE_INT32 EncryptSendRequest(REQ_TYPE &req, WRAPPER_TYPE &wrapper, const DSC::CDscShortBlob &envelopeKey, ACE_UINT32 nHandleID);


	ACE_INT32 LoadPeerInfo(void);
	ACE_INT32 ConnectRegServer(void);
	ACE_INT32 ConnectVbeServer(CVbePeer *vbeServer);

	register_user_session_map_type m_mapRegisterUserSession;
	login_session_map_type m_mapLoginSession;
	transfer_session_map_type m_mapTransferSession;
	get_userinfo_session_map_type m_mapGetUserInfoSession;

	online_user_session_map_type m_mapOnlineUsers;

	ACE_UINT32 m_nSessionID = 1;
	ACE_UINT32 m_seed = 0;
	ACE_UINT32 m_nTokenSeq = 0;

	CVbePeer* m_pRegServer = nullptr;
	DSC::CDscList <CVbePeer*> m_lstVbePeers;
	vbe_peer_map_type m_mapVbePeers;

	VBE_SDK::IClientSdkMsgCallback *m_pCallback = nullptr;
	DSC::CDscShortBlob m_peerEnvelopeKey;
	bool m_bReady = false;

};

#include "vbe/vbe_client_service/vbe_client_service.inl"

#endif
