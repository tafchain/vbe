#include "dsc/dispatcher/dsc_dispatcher_center.h"
#include "dsc/service/dsc_service_container.h"
#include "dsc/db/per/persistence.h"
#include "dsc/dsc_database_factory.h"

#include "vbe/vbe_hls/vbe_hls_service.h"
#include "vbe/vbe_hls/vbe_hls_service_plugin.h"


class CHlsConfig
{
public:
	CHlsConfig()
		: m_hlsID("HLS_ID")
		, m_channelID("CH_ID")
	{
	}

public:
	PER_BIND_ATTR(m_hlsID, m_channelID);

public:
	CColumnWrapper< ACE_INT32 > m_hlsID;
	CColumnWrapper< ACE_INT32 > m_channelID;
};


class CHlsCriterion : public CSelectCriterion
{
public:
	virtual void SetCriterion(CPerSelect& rPerSelect)
	{
		rPerSelect.Where(rPerSelect["NODE_ID"] == CDscAppManager::Instance()->GetNodeID());
	}
};

CVbeHlsServicePlugin::CVbeHlsServicePlugin()
{
}

ACE_INT32 CVbeHlsServicePlugin::OnInit(void)
{
	CDscDatabase database;
	CDBConnection dbConnection;
	ACE_INT32 nRet = CDscDatabaseFactoryDemon::instance()->CreateDatabase(database, dbConnection);

	if (nRet)
	{
		DSC_RUN_LOG_ERROR("connect database failed.");
	}
	else
	{
		CTableWrapper< CCollectWrapper<CHlsConfig> > lstCfg("HLS_CFG");
		CHlsCriterion criterion;

		nRet = ::PerSelect(lstCfg, database, dbConnection, &criterion);
		if (nRet)
		{
			DSC_RUN_LOG_ERROR("select from HLS_CFG failed");
		}
		else
		{
			CVbeHlsService* pHls;
			ACE_UINT32 nChannelID;
			ACE_UINT16 nHlsID;

			for (auto it = lstCfg->begin(); it != lstCfg->end(); ++it)
			{
				nChannelID = *it->m_channelID;
				nHlsID = *it->m_hlsID;

				DSC_NEW(pHls, CVbeHlsService(nChannelID));

				nRet = CDscDispatcherCenterDemon::instance()->RegistDscTask(pHls, CVbeHlsService::EN_SERVICE_TYPE, nHlsID, true);
				if (nRet)
				{
					DSC_RUN_LOG_ERROR("regist dsc task failed, xcs-id:%d.", nHlsID);
					break;
				}
			}
		}

		if (nRet)
		{
			DSC_RUN_LOG_ERROR("regist hls failed");
		}
		else
		{
			DSC_RUN_LOG_FINE("regist hls succeed");
		}
	}

	return nRet;
}

#ifndef DSC_TEST
extern "C" PLUGIN_EXPORT IDscPlugin* CreateDscPlugin(void)
{
	CVbeHlsServicePlugin* pPlugIn = NULL;

	DSC_NEW(pPlugIn, CVbeHlsServicePlugin);

	return pPlugIn;
}
#endif
