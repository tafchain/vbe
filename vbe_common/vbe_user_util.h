#ifndef _VBE_USER_UTIL_H_50105612878251214688
#define _VBE_USER_UTIL_H_50105612878251214688

#include "vbe/vbe_common/vbe_common_def.h"


#include "dsc/codec/codec_base/dsc_codec_base.h"

namespace VBE
{
	
	class VBE_EXPORT CVbeUserUtil
	{
	public:
		// ��vbh userkey + channelID ת��Ϊ vbe userkey
		// ���������ͷ�outVbeUserKey�ڴ�
		static void EncodeVbeUserKey(DSC::CDscShortBlob& outVbeUserKey, DSC::CDscShortBlob& inVbhUserKey, ACE_UINT32 inChannleID);

		// ��vbe userkeyת��Ϊ vbh userkey + channelID
		static ACE_INT32 DecodeVbeUserKey(DSC::CDscShortBlob& outVbhUserKey, ACE_UINT32 &outChannleID, DSC::CDscShortBlob& inVbeUserKey);

		static ACE_UINT64 GetHashKey(DSC::CDscShortBlob & inVbhUserKey);
	};
}







#endif
