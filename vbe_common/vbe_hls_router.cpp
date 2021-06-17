#include "vbe/vbe_common/vbe_hls_router.h"
#include "vbe/vbe_common/vbe_common_def.h"

namespace VBE
{
	CVbeHlsRouter::CVbeHlsRouter()
	{
	}

	CVbeHlsRouter::~CVbeHlsRouter()
	{
		ClearChannelMap();
	}

	ACE_INT32 CVbeHlsRouter::Open(void)
	{
		if (LoadChannelMapHlsAddr())
		{
			DSC_RUN_LOG_ERROR("load channel map vbe hls addr failed.");

			return -1;
		}

		return 0;
	}

	ACE_INT32 CVbeHlsRouter::GetHlsAddr(CDscMsg::CDscMsgAddr& addr, const ACE_UINT32 nChannelID)
	{
		//查找用户对应的tcs地址
		auto pAddr = m_mapChannelMapHlsAddr.find(nChannelID);

		if (pAddr != m_mapChannelMapHlsAddr.end())
		{
			addr.SetNodeType(VBE::EN_VBE_SERVICE_APP_TYPE);
			addr.SetNodeID(pAddr->second->m_nNodeID);
			addr.SetServiceType(VBE::EN_VBE_HLS_SERVICE_TYPE);
			addr.SetServiceID(pAddr->second->m_nServiceID);

			return 0;
		}
		else
		{
			return -1;
		}
	}

	class CVbeHlsConfig
	{
	public:
		CVbeHlsConfig()
			: m_nodeID("NODE_ID")
			, m_hlsID("HLS_ID")
			, m_channelID("CH_ID")
		{
		}

	public:
		PER_BIND_ATTR(m_nodeID, m_hlsID, m_channelID);

	public:
		CColumnWrapper< ACE_INT32 > m_nodeID;
		CColumnWrapper< ACE_INT32 > m_hlsID;
		CColumnWrapper< ACE_UINT32 > m_channelID;
	};

	ACE_INT32 CVbeHlsRouter::LoadChannelMapHlsAddr()
	{
		CDscDatabase database;
		CDBConnection dbConnection;
		ACE_INT32 nRet = CDscDatabaseFactoryDemon::instance()->CreateDatabase(database, dbConnection);

		if (nRet)
		{
			DSC_RUN_LOG_ERROR("connect database failed.");

			return -1;
		}

		CTableWrapper< CCollectWrapper<CVbeHlsConfig> > lstCfg("HLS_CFG");

		nRet = ::PerSelect(lstCfg, database, dbConnection);
		if (nRet)
		{
			DSC_RUN_LOG_ERROR("select from HLS_CFG failed");

			return -1;
		}
		else
		{
			CDscAddr* pAddr = DSC_THREAD_TYPE_NEW(CDscAddr) CDscAddr();
			ACE_UINT32 nChannelID;

			ClearChannelMap();

			for (auto it = lstCfg->begin(); it != lstCfg->end(); ++it)
			{
				pAddr->m_nNodeID = *it->m_nodeID;
				pAddr->m_nServiceID = *it->m_hlsID;
				nChannelID = *it->m_channelID;

				m_mapChannelMapHlsAddr[nChannelID] = pAddr;
			}

			if (m_mapChannelMapHlsAddr.size() == 0)
			{
				return -1;
			}
		}

		return 0;
	}

	void CVbeHlsRouter::ClearChannelMap()
	{
		for (auto &it : m_mapChannelMapHlsAddr)
		{
			DSC_THREAD_TYPE_DELETE(it.second);
		}
		m_mapChannelMapHlsAddr.clear();
	}


}