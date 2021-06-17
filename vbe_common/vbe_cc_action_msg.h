#ifndef _VBE_CC_ACTION_MSG_H_01237027697202
#define _VBE_CC_ACTION_MSG_H_01237027697202

#include "vbe/vbe_common/vbe_common_def.h"

#include "dsc/codec/dsc_codec/dsc_codec.h"


namespace VBE
{
	class CVbeCcActionTransferMsg
	{
	public:
		DSC_BIND_ATTR(m_nTotalCoin, m_sponsorUserKey, m_lstUserKey, m_lstCoin);

	public:
		ACE_UINT32 m_nTotalCoin;
		DSC::CDscShortBlob m_sponsorUserKey;// vbe user key
		DSC::CDscShortList<DSC::CDscShortBlob> m_lstUserKey;	// vbe user key
		DSC::CDscShortList<ACE_UINT32> m_lstCoin;
	};
}










#endif