#ifndef _VBE_PROPOSE_MANAGER_H_089025607986151
#define _VBE_PROPOSE_MANAGER_H_089025607986151
#include "dsc/codec/dsc_codec/dsc_codec.h"
#include "dsc/storage/small_block_storage/small_block_storage.h"

class CStorageProposeItem
{
public:
	DSC_BIND_ATTR(m_bMain, m_propose);
public:
	bool m_bMain;
	DSC::CDscShortList<ACE_UINT32> m_lstChannelID; // »¹Î´·¢ËÍµÄchannel
	DSC::CDscShortBlob m_sponsorUserKey;
	DSC::CDscShortBlob m_propose;
};

class CVbeProposeManager
{
public:
	CVbeProposeManager();
	~CVbeProposeManager();

public:
	ACE_INT32 Init();
	ACE_INT32 InsertPropose(SBS::SbsRecord& record, CStorageProposeItem& item);
	ACE_INT32 DeletePropose(SBS::SbsRecord& record);

private:
	CSmallBlockStorage m_dbPropose;
};


#endif
