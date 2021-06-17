#include "vbe/vbe_service/vbh_agent_service.h"
#include "vbe/vbe_service/vbe_service.h"

CVbhAgentService::CVbhAgentService()
{
}

ACE_INT32 CVbhAgentService::OnInit(void)
{
	if (CVbhAdapterBase::OnInit())
	{
		DSC_RUN_LOG_ERROR("transform agent service init failed!");

		return -1;
	}

	return 0;
}

ACE_INT32 CVbhAgentService::OnExit(void)
{
	return 0;
}

void CVbhAgentService::OnQueryUserInfoResponse(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, const DSC::CDscShortBlob& userInfo)
{
	m_pVbeService->OnQueryUserInfoResponse(nReturnCode, nRequestID, userInfo);
}

void CVbhAgentService::OnQueryTransactionInfoResponse(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, const DSC::CDscBlob& tranInfo)
{
	m_pVbeService->OnQueryTransactionInfoResponse(nReturnCode, nRequestID, tranInfo);
}


void CVbhAgentService::SetVbeService(CVbeService* pSrv)
{
	m_pVbeService = pSrv;
}
