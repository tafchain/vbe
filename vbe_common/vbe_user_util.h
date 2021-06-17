#ifndef _VBE_USER_UTIL_H_50105612878251214688
#define _VBE_USER_UTIL_H_50105612878251214688

#include "vbe/vbe_common/vbe_common_def.h"


#include "dsc/codec/codec_base/dsc_codec_base.h"

namespace VBE
{
	
	class VBE_EXPORT CVbeUserUtil
	{
	public:
		// 将vbh userkey + channelID 转换为 vbe userkey
		// 调用者需释放outVbeUserKey内存
		static void EncodeVbeUserKey(DSC::CDscShortBlob& outVbeUserKey, DSC::CDscShortBlob& inVbhUserKey, ACE_UINT32 inChannleID);

		// 将vbe userkey转换为 vbh userkey + channelID
		static ACE_INT32 DecodeVbeUserKey(DSC::CDscShortBlob& outVbhUserKey, ACE_UINT32 &outChannleID, DSC::CDscShortBlob& inVbeUserKey);

		static ACE_UINT64 GetHashKey(DSC::CDscShortBlob & inVbhUserKey);
	};
}







#endif
