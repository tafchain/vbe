#include "vbe/vbe_reg_service/vbe_reg_service_plugin.h"
#include "vbe/vbe_reg_service/vbe_reg_service.h"

#include "dsc/plugin/dsc_service_factory.h"
#include "dsc/service/dsc_service_container.h"
#include "dsc/db/per/persistence.h"
#include "dsc/dsc_database_factory.h"


CDscService* CVbeRegServiceFactory::CreateDscService(void)
{
	CVbeRegService* pRegService = NULL;

	DSC_NEW(pRegService, CVbeRegService(m_strAddr, m_nPort));

	if (pRegService)
	{
		pRegService->SetType(CVbeRegService::EN_SERVICE_TYPE);
		pRegService->SetID(m_nServiceID);
	}

	return pRegService;
}



class CRegServerCfg
{
public:
	CRegServerCfg()
		:m_ipAddr("IP_ADDR")
		, m_port("PORT")
		, m_regID("REG_ID")
	{
	}

public:
	PER_BIND_ATTR(m_ipAddr, m_port, m_regID);

public:
	CColumnWrapper< CDscString > m_ipAddr;
	CColumnWrapper< ACE_INT32 > m_port;
	CColumnWrapper< ACE_INT32 > m_regID;
};

class CCpsCfgCriterion : public CSelectCriterion
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

	CTableWrapper< CCollectWrapper<CRegServerCfg> > lstRegCfg("VBE_REG_ADDR");
	CCpsCfgCriterion criterion;

	if (::PerSelect(lstRegCfg, database, dbConnection, &criterion))
	{
		DSC_RUN_LOG_ERROR("select from VBE_REG_ADDR failed");

		return -1;
	}

	for (auto it = lstRegCfg->begin(); it != lstRegCfg->end(); ++it)
	{
		CVbeRegServiceFactory serviceFactory;

		serviceFactory.m_nServiceID = *it->m_regID;
		serviceFactory.m_strAddr = *it->m_ipAddr;
		serviceFactory.m_nPort = *it->m_port;
		
		ACE_INT32 nRet = ::RegistOneReactorDscService(&serviceFactory);

		if (nRet)
		{
			DSC_RUN_LOG_ERROR("regist user service regist failed");
		}
		else
		{
			DSC_RUN_LOG_FINE("regist user service regist successfully");
		}
		return nRet;
	}

	return -1;

	
}

extern "C" PLUGIN_EXPORT void* CreateDscPlugin(void)
{
	CSdkClientServicePlugIn* pPlugIn = NULL;

	DSC_NEW(pPlugIn, CSdkClientServicePlugIn);

	return pPlugIn;
}
