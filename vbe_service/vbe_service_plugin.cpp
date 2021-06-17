#include "vbe/vbe_service/vbe_service_plugin.h"
#include "vbe/vbe_service/vbe_service.h"
#include "vbe/vbe_service/vbh_agent_service.h"
#include "vbe/vbe_service/vbh_agent_service_factory.h"

#include "dsc/plugin/dsc_service_factory.h"
#include "dsc/service/dsc_service_container.h"
#include "dsc/db/per/persistence.h"
#include "dsc/dsc_database_factory.h"
#include "dsc/dispatcher/dsc_dispatcher_center.h"


CDscService* CVbeServiceFactory::CreateDscService(void)
{
	return m_vbeService;
}



class CVbeServerCfg
{
public:
	CVbeServerCfg()
		:m_ipAddr("IP_ADDR")
		, m_port("PORT")
		, m_vbeID("VBE_ID")
	{
	}

public:
	PER_BIND_ATTR(m_ipAddr, m_port, m_vbeID);

public:
	CColumnWrapper< CDscString > m_ipAddr;
	CColumnWrapper< ACE_INT32 > m_port;
	CColumnWrapper< ACE_INT32 > m_vbeID;
};

class CCfgCriterion : public CSelectCriterion
{
public:
	virtual void SetCriterion(CPerSelect& rPerSelect)
	{
		rPerSelect.Where(rPerSelect["NODE_ID"] == CDscAppManager::Instance()->GetNodeID());
	}
};

ACE_INT32 CSdkClientServicePlugIn::OnInit(void)
{
	CDscDatabase database;
	CDBConnection dbConnection;

	if (CDscDatabaseFactoryDemon::instance()->CreateDatabase(database, dbConnection))
	{
		DSC_RUN_LOG_ERROR("connect database failed.");

		return -1;
	}

	CTableWrapper< CCollectWrapper<CVbeServerCfg> > lstCfg("VBE_ADDR");
	CCfgCriterion criterion;

	if (::PerSelect(lstCfg, database, dbConnection, &criterion))
	{
		DSC_RUN_LOG_ERROR("select from VBE_ADDR failed");

		return -1;
	}

	CDscReactorServiceContainerFactory dscReactorServiceContainerFactory;
	IDscTask* pDscServiceContainer = nullptr;
	ACE_UINT16 nContainerID = 1;

	//RegistDscReactorServiceContainer(NULL, VBE::EN_VBE_SERVICE_CONTAINER_TYPE, lstCfg->size());

	for (auto it = lstCfg->begin(); it != lstCfg->end(); ++it)
	{
		//2.×¢²ácontainer
		CDscDispatcherCenterDemon::instance()->AcquireWrite();
		pDscServiceContainer = CDscDispatcherCenterDemon::instance()->GetDscTask_i(VBE::EN_VBE_SERVICE_CONTAINER_TYPE, nContainerID);
		if (!pDscServiceContainer)
		{
			pDscServiceContainer = dscReactorServiceContainerFactory.CreateDscServiceContainer();
			if (CDscDispatcherCenterDemon::instance()->RegistDscTask_i(pDscServiceContainer, VBE::EN_VBE_SERVICE_CONTAINER_TYPE, nContainerID))
			{
				DSC_RUN_LOG_ERROR("regist endorser container error, type:%d, id:%d.", VBE::EN_VBE_SERVICE_CONTAINER_TYPE, nContainerID);
				return -1;
			}
		}
		if (!pDscServiceContainer)
		{
			DSC_RUN_LOG_ERROR("cann't create container.");
			CDscDispatcherCenterDemon::instance()->Release();

			return -1;
		}
		CDscDispatcherCenterDemon::instance()->Release();
		++nContainerID;

		CVbeService* pVbeService = DSC_THREAD_TYPE_NEW(CVbeService) CVbeService(*it->m_ipAddr, *it->m_port);
		CVbhAgentService* pAgentService = DSC_THREAD_TYPE_NEW(CVbhAgentService) CVbhAgentService();
		CVbeServiceFactory vbeFactory;
		CVbhAgentServiceFactory vbhaFactory;



		pVbeService->SetType(CVbeService::EN_SERVICE_TYPE);
		pVbeService->SetID(*it->m_vbeID);
		pVbeService->SetVbhAgentService(pAgentService);
		vbeFactory.m_vbeService = pVbeService;

		pAgentService->SetType(VBE::EN_VBE_VBH_AGENT_SERVICE_TYPE);
		pAgentService->SetID(*it->m_vbeID);
		pAgentService->SetVbeService(pVbeService);
		vbhaFactory.m_pHas = pAgentService;


		//4.×¢²áendorser-service + tranfer-agent-service
		CDscSynchCtrlMsg ctrlMsg(DSC::EN_REGIST_SERVICE_CONTAINER_MSG, &vbeFactory);

		if (pDscServiceContainer->PostDscMessage(&ctrlMsg))
		{
			DSC_RUN_LOG_ERROR("When regist endoser-service-factory, Failed to push queue at container:%d.", VBH::EN_ENDORSER_SERVICE_CONTAINER_TYPE);

			return -1;
		}

		CDscSynchCtrlMsg ctrlMsgHas(DSC::EN_REGIST_SERVICE_CONTAINER_MSG, &vbhaFactory);

		if (pDscServiceContainer->PostDscMessage(&ctrlMsgHas))
		{
			DSC_RUN_LOG_ERROR("When regist transfer-agent-service-factory, Failed to push queue at container:%d.", VBH::EN_ENDORSER_SERVICE_CONTAINER_TYPE);

			return -1;
		}

		return 0;
	}

	return -1;
}

extern "C" PLUGIN_EXPORT void* CreateDscPlugin(void)
{
	CSdkClientServicePlugIn* pPlugIn = NULL;

	DSC_NEW(pPlugIn, CSdkClientServicePlugIn);

	return pPlugIn;
}
