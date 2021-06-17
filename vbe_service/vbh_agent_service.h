#ifndef _VBH_AGENT_SERVICE_H_017456910847614676
#define _VBH_AGENT_SERVICE_H_017456910847614676

#include "dsc/protocol/hts/dsc_hts_service.h"
#include "dsc/protocol/mcp/mcp_asynch_acceptor.h"
#include "dsc/container/bare_hash_map.h"

#include "vbh/common/vbh_comm_msg_def.h"
#include "vbh/sdk/vbh_adapter_base/vbh_adapter_base.h"

class CVbeService;
class PLUGIN_EXPORT CVbhAgentService : public CVbhAdapterBase
{
public:
	CVbhAgentService();

public:
	virtual ACE_INT32 OnInit(void);
	virtual ACE_INT32 OnExit(void);

	// INTERFACE OVERRIDE CVbhAdapterBase
public:
	virtual void OnQueryUserInfoResponse(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, const DSC::CDscShortBlob& userInfo) override;
	virtual void OnQueryTransactionInfoResponse(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, const DSC::CDscBlob& tranInfo) override;


public:
	void SetVbeService(CVbeService* pSrv);

private:
	enum
	{
		EN_HASH_MAP_BITES = 16,
		EN_SESSION_TIMEOUT_VALUE = 60
	};

	CVbeService* m_pVbeService = nullptr;
};




#endif
