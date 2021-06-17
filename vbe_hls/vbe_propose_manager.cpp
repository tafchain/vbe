#include "vbe/vbe_hls/vbe_propose_manager.h"
#include "dsc/dsc_log.h"

CVbeProposeManager::CVbeProposeManager()
{
}

CVbeProposeManager::~CVbeProposeManager()
{
}

ACE_INT32 CVbeProposeManager::Init()
{
	// TODO ²ÎÊý
	CDscString strStoragePathName;
	CDscString strBlockIdStackPathName;
	CDscString strPageCachePathName;
	CDscString strPageHeadCachePathName;
	bool bDirectIO = true;

	auto nReturnCode = m_dbPropose.OpenStorage(strStoragePathName, strBlockIdStackPathName, strPageCachePathName, strPageHeadCachePathName, bDirectIO);

	if (nReturnCode)
	{
		DSC_RUN_LOG_ERROR("open storage failed %d", nReturnCode);

		return nReturnCode;
	}

	return 0;
	return ACE_INT32();
}

ACE_INT32 CVbeProposeManager::InsertPropose(SBS::SbsRecord& record, CStorageProposeItem& item)
{
	return m_dbPropose.Insert(record, item);
}

ACE_INT32 CVbeProposeManager::DeletePropose(SBS::SbsRecord& record)
{
	return m_dbPropose.DeleteBlock(record);
}
