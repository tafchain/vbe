#ifndef _HLS_SERVICE_H_67946723451773578
#define _HLS_SERVICE_H_67946723451773578

#include "dsc/dsc_reactor.h"
#include "dsc/container/dsc_type_array.h"
#include "dsc/container/bare_hash_map.h"

#include "vbe/vbe_hls/vbe_user_manager.h"
#include "vbe/vbe_hls/vbe_propose_manager.h"
#include "vbe/vbe_common/vbe_common_msg.h"
#include "vbe//vbe_common/vbe_user_util.h"

#include "vbe/vbe_common/vbe_hls_router.h"

#include "vbh/sdk/vbh_adapter_base/vbh_adapter_base.h"

class PLUGIN_EXPORT CVbeHlsService : public CVbhAdapterBase
{
public:
	enum
	{
		EN_SERVICE_TYPE = VBE::EN_VBE_HLS_SERVICE_TYPE,

		EN_HASH_MAP_BITES = 16,
		EN_SESSION_TIMEOUT = 60,
		EN_MAX_RETRY_PROPOSE_TIMES = 3,
	};

public:
	CVbeHlsService(const ACE_UINT32 nChannelID);

public:
	virtual ACE_INT32 OnInit(void) override;
	virtual ACE_INT32 OnExit(void) override;

	// INTERFACE OVERRIDE CVbhAdapterBase
public:
	virtual void OnRegistUserResponse(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, const DSC::CDscShortBlob& userKey) override;
	virtual void OnRegistUserResultNotify(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID) override;
	virtual void OnProposeResponse(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, const DSC::CDscShortBlob& transKey) override;
	virtual void OnProposeResultNotify(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID) override;
	virtual void OnQueryUserInfoResponse(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, const DSC::CDscShortBlob& userInfo) override;
	virtual void OnQueryTransactionInfoResponse(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, const DSC::CDscBlob& tranInfo) override;

protected:
	BEGIN_BIND_DSC_MESSAGE
		DSC_BIND_MESSAGE(VBE::CRegisterUserRegHlsReq)
		DSC_BIND_MESSAGE(VBE::CCheckUsersVbeHlsReq)
		DSC_BIND_MESSAGE(VBE::CTransferVbeHlsReq)
		DSC_BIND_MESSAGE(VBE::CTransferHlsHlsReq)

		DSC_BIND_MESSAGE(VBE::CTransferHlsHlsRsp)

		END_BIND_DSC_MESSAGE

public:
	void OnDscMsg(VBE::CRegisterUserRegHlsReq& rRegisterUserReq, const CDscMsg::CDscMsgAddr& rSrcMsgAddr);
	void OnDscMsg(VBE::CCheckUsersVbeHlsReq& rCheckUsersReq, const CDscMsg::CDscMsgAddr& rSrcMsgAddr);
	void OnDscMsg(VBE::CTransferVbeHlsReq& rTransferReq, const CDscMsg::CDscMsgAddr& rSrcMsgAddr);
	void OnDscMsg(VBE::CTransferHlsHlsReq& rTransferReq, const CDscMsg::CDscMsgAddr& rSrcMsgAddr);

	void OnDscMsg(VBE::CTransferHlsHlsRsp& rTransferRsp, const CDscMsg::CDscMsgAddr& rSrcMsgAddr);


private:

	// 向vbh发请求的session，vbh sdk已处理timeout，net error，所以这里不需要这两个回调
	class IHlsBaseSession
	{
	public:
		IHlsBaseSession() = default;
		IHlsBaseSession(const IHlsBaseSession&) = delete;
		IHlsBaseSession& operator=(const IHlsBaseSession&) = delete;

	public:
		CDscMsg::CDscMsgAddr m_srcMsgAddr;
		ACE_UINT32 m_nHlsSessionID; //客户端sessionID
		ACE_UINT32 m_nCltSessionID; //发送业务请求方的sessionID

	public:
		ACE_UINT32 m_nIndex = 0; //使用 CDscTypeArray 容器必须具备的接口
	};

	class IHlsBaseTimerSession : public IHlsBaseSession, public CDscServiceTimerHandler
	{
	public:
		IHlsBaseTimerSession(CVbeHlsService& rHlsService);

		virtual void OnNetError(void) = 0;
	public:
		CVbeHlsService& m_rHlsService;
	};

	//注册用户的session
	class CHlsRegisterUserSession : public IHlsBaseSession
	{
	public:
		~CHlsRegisterUserSession();
	public:
		DSC::CDscShortBlob m_userKey;
		DSC::CDscShortBlob m_cryptUserKey;

	public:
		ACE_UINT32 m_nKey = 0; 
		CHlsRegisterUserSession* m_pPrev = NULL; 
		CHlsRegisterUserSession* m_pNext = NULL; 
	};
	
	class CHlsCheckUserQuerySession;
	class CHlsCheckUserSession : public IHlsBaseSession
	{
	public:
		CHlsCheckUserSession();
	public:
		dsc_unordered_map_type(ACE_UINT64, bool) m_mapUserHashKey;
		CDscTypeArray<CHlsCheckUserQuerySession> m_arrCheckUserQuery;

	public:
		ACE_UINT32 m_nKey = 0;
		CHlsCheckUserSession* m_pPrev = NULL;
		CHlsCheckUserSession* m_pNext = NULL;
	};
	// 本地cache没找到，需要到vbh查询的session
	class CHlsCheckUserQuerySession : public IHlsBaseSession
	{
	public:
		CHlsCheckUserQuerySession();
	public:
		CHlsCheckUserSession* m_pCheckUserSession;
		ACE_UINT64 m_nUserHashKey;

	public:
		ACE_UINT32 m_nIndex = 0; //使用 CDscTypeArray 容器必须具备的接口

	public:
		ACE_UINT32 m_nKey = 0;
		CHlsCheckUserQuerySession* m_pPrev = NULL;
		CHlsCheckUserQuerySession* m_pNext = NULL;
	};

	class CHlsTransferToHlsSession;
	class CHlsTransferSession : public IHlsBaseTimerSession
	{
	public:
		CHlsTransferSession(CVbeHlsService& rService);
		~CHlsTransferSession();

	public:
		virtual void OnTimer(void) override;
		virtual void OnNetError(void) override;

	public:
		DSC::CDscShortList<ACE_UINT64> m_lstUserHashKey;
		CDscTypeArray<CHlsTransferToHlsSession> m_arrTransferToHlsSession;
		DSC::CDscShortBlob m_transKey;
		SBS::SbsRecord* m_dbRecord;
		CStorageProposeItem m_dbProposeItem;
		ACE_UINT32 m_nRetryTimes;

	public:
		ACE_UINT32 m_nKey = 0;
		CHlsTransferSession* m_pPrev = NULL;
		CHlsTransferSession* m_pNext = NULL;
	};

	class CHlsTransferToHlsSession : public IHlsBaseTimerSession
	{
	public:
		CHlsTransferToHlsSession(CVbeHlsService& rService);
		~CHlsTransferToHlsSession();

	public:
		virtual void OnTimer(void) override;
		virtual void OnNetError(void) override;

	public:
		CHlsTransferSession* m_pTransferSession;
		ACE_UINT32 m_nChannelID;
		ACE_UINT32 m_nRetryTimes;

public:
		ACE_UINT32 m_nIndex = 0; //使用 CDscTypeArray 容器必须具备的接口

	public:
		ACE_UINT32 m_nKey = 0;
		CHlsTransferToHlsSession* m_pPrev = NULL;
		CHlsTransferToHlsSession* m_pNext = NULL;
	};

public:
	void OnTimeOut(CHlsTransferToHlsSession* pTransferToHlsSession);
	void OnNetworkError(CHlsTransferToHlsSession* pTransferToHlsSession);

	void OnTimeOut(CHlsTransferSession*);
	void OnNetworkError(CHlsTransferSession*);

public:
	using register_user_map_type = CBareHashMap<ACE_UINT32, CHlsRegisterUserSession, EN_HASH_MAP_BITES>;
	using check_users_query_map_type = CBareHashMap<ACE_UINT32, CHlsCheckUserQuerySession, EN_HASH_MAP_BITES>;
	using transfer_map_type = CBareHashMap<ACE_UINT32, CHlsTransferSession, EN_HASH_MAP_BITES>;
	using transfer_tohls_map_type = CBareHashMap<ACE_UINT32, CHlsTransferToHlsSession, EN_HASH_MAP_BITES>;

	using user_transfer_queue_map_type = dsc_unordered_map_type(ACE_UINT64, dsc_list_type(CHlsTransferSession*)); // hash key => session

private:
	
	void ReleaseCheckUserSession(CHlsCheckUserSession* pCheckSession);
	void ReleaseTransferSession(CHlsTransferSession* pTransferSession);
	ACE_INT32 DecodePropose(CHlsTransferSession* pTransferSession, DSC::CDscShortBlob& propose);
	void MaybePropose(CHlsTransferSession *pTransferSession);
	bool OnProposeFailed(ACE_INT32 nReturnCode, CHlsTransferSession* pTransferSession);
	void OnProposeSuccess(CHlsTransferSession* pTransferSession);
	void MaybeRetryProposeOnFailed(ACE_INT32 nReturnCode, CHlsTransferSession* pTransferSession);
	ACE_INT32 SendProposeToHls(CHlsTransferSession* pTransferSession, ACE_UINT32 nChannelID);

	void ResponseCheckUserReq(ACE_INT32 nReturnCode, CHlsCheckUserSession* pCheckSession);

	void ResponseTransferReq(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, const CDscMsg::CDscMsgAddr& rSrcMsgAddr, DSC::CDscShortBlob &transKey);
	void ResponseTransferReq(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, const CDscMsg::CDscMsgAddr& rSrcMsgAddr);
	void ResponseTransferHlsReq(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, const CDscMsg::CDscMsgAddr& rSrcMsgAddr);



	template<typename MAP_TYPE, typename TYPE>
	void InsertSession(MAP_TYPE& mapSession, TYPE* session, const CDscMsg::CDscMsgAddr& mcpHandle);
	template<typename MAP_TYPE>
	CVbeHlsService::IHlsBaseSession* EraseSession(MAP_TYPE& mapSession, ACE_UINT32 sessionID);
	template<typename MAP_TYPE>
	CVbeHlsService::IHlsBaseSession* EraseTimerSession(MAP_TYPE& mapSession, ACE_UINT32 sessionID);
	template<typename MAP_TYPE>
	CVbeHlsService::IHlsBaseSession* FindSession(MAP_TYPE& mapSession, ACE_UINT32 sessionID);

	register_user_map_type m_mapRegisterUser;
	check_users_query_map_type m_mapCheckUserQuery;
	transfer_map_type m_mapTransfer;
	transfer_tohls_map_type m_mapTransferToHls;

	user_transfer_queue_map_type m_mapUserTransferQueue;

	CVbeUserManager m_userManager;
	CVbeProposeManager m_proposeManager;
	
	VBE::CVbeHlsRouter m_hlsRouter;
	ACE_UINT32 m_nChannelID;
	ACE_UINT32 m_nHlsSessionID = 1;

	
};

#include "vbe/vbe_hls/vbe_hls_service.inl"





#endif // !_VBE_SERVICE_H_0951345980123479
