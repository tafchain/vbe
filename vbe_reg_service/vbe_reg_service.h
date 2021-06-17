#ifndef _VBE_REG_SERVICE_H_01508246982627
#define _VBE_REG_SERVICE_H_01508246982627

#include "vbe/vbe_common/vbe_common_msg.h"

#include "dsc/protocol/hts/dsc_hts_service.h"
#include "dsc/protocol/mcp/mcp_asynch_acceptor.h"
#include "dsc/container/bare_hash_map.h"
#include "dsc/protocol/mcp/mcp_server_handler.h"

class CVbeChannelAllocator;
class PLUGIN_EXPORT CVbeRegService : public CDscHtsServerService
{
public:
	enum
	{
		EN_HASH_MAP_BITES = 16,
		EN_SESSION_TIMEOUT_VALUE = 60,

		EN_SERVICE_TYPE = VBE::EN_VBE_REG_SERVICE_TYPE
	};

public:
	CVbeRegService(const CDscString& strIpAddr, const ACE_INT32 nPort);
	virtual ACE_INT32 OnInit(void) override;
	virtual ACE_INT32 OnExit(void) override;


protected:
	BEGIN_HTS_MESSAGE_BIND
	BIND_HTS_MESSAGE(VBE::CRegisterUserCltRegReq)
	END_HTS_MESSAGE_BIND

public:
	ACE_INT32 OnHtsMsg(VBE::CRegisterUserCltRegReq& rRegistUser, CMcpHandler* pMcpHandler);

protected:
	BEGIN_BIND_DSC_MESSAGE
	DSC_BIND_MESSAGE(VBE::CRegisterUserHlsRegRsp)
	END_BIND_DSC_MESSAGE

public:
	void OnDscMsg(VBE::CRegisterUserHlsRegRsp& rRegistUserRsp, const CDscMsg::CDscMsgAddr& rSrcMsgAddr);


private:

	class CVbeRegServiceHandler;

	class IUserSession : public CDscServiceTimerHandler
	{
	public:
		IUserSession(CVbeRegService& rRegService);
		IUserSession(const IUserSession&) = delete;
		IUserSession& operator= (const IUserSession&) = delete;
	public:
		virtual void OnNetError(void) = 0;

	public:
		ACE_UINT32 m_nRegSessionID;
		ACE_UINT32 m_nCltSessionID;
		CVbeRegServiceHandler* m_pRegServiceHandler;

	public:
		ACE_UINT32 m_nIndex = 0;

	protected:
		CVbeRegService& m_rRegService;
	};

	class CRegisterUserSession : public IUserSession
	{
	public:
		CRegisterUserSession(CVbeRegService& rRegService);
		~CRegisterUserSession();
	public:
		virtual void OnTimer(void) override;
		virtual void OnNetError(void) override;

	public:
		DSC::CDscShortBlob m_nonce;
	public:
		ACE_UINT32 m_nKey = 0;
		CRegisterUserSession* m_pPrev = NULL;
		CRegisterUserSession* m_pNext = NULL;
	};

	class CVbeRegServiceHandler : public CMcpServerHandler
	{
	public:
		CVbeRegServiceHandler(CMcpServerService& rService, ACE_HANDLE handle, const ACE_INT32 nHandleID);

	public:
		CDscTypeArray<IUserSession> m_arrUserSession;
	};

private:
	void OnTimeOut(CRegisterUserSession* pRegSession);
	void OnNetworkError(CRegisterUserSession* pRegSession);

private:
	using reg_session_map_type = CBareHashMap<ACE_UINT32, CRegisterUserSession, EN_HASH_MAP_BITES>;

private:
	void OnRegisterUserResponse(ACE_INT32 nHandleID, ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, DSC::CDscShortBlob& nonce, DSC::CDscShortBlob* userKey = nullptr);

	template<typename MAP_TYPE, typename TYPE>
	void InsertSession(MAP_TYPE& mapSession, TYPE* session, CMcpHandler* mcpHandle);
	template<typename MAP_TYPE>
	IUserSession* EraseSession(MAP_TYPE& mapSession, ACE_UINT32 sessionID);

	

	ACE_UINT32 AllocChannel();

	virtual CMcpServerHandler* AllocMcpHandler(ACE_HANDLE handle) override;

private:
	reg_session_map_type m_mapRegSession;
	ACE_UINT32 m_nSessionID = 1;

	CVbeChannelAllocator* m_channelAllocator;

	DSC::CDscShortBlob m_peerEnvelopeKey;

	const CDscString m_strIpAddr;
	const ACE_INT32 m_nPort;
	CMcpAsynchAcceptor<CVbeRegService>* m_pAcceptor = NULL;
};

#include "vbe/vbe_reg_service/vbe_reg_service.inl"


#endif
