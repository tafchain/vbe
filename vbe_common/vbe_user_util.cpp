#include "vbe/vbe_common/vbe_user_util.h"
#include "dsc/codec/dsc_codec/dsc_codec.h"

class CVbeUserKey
{
public:
	CVbeUserKey(DSC::CDscShortBlob& vbhUserKey, ACE_UINT32& nChannleID): m_vbhUserKey(vbhUserKey), m_nChannelID(nChannleID){}
public:
	DSC_BIND_ATTR(m_vbhUserKey, m_nChannelID);
public:
	DSC::CDscShortBlob& m_vbhUserKey;
	ACE_UINT32& m_nChannelID;
};

class CVbhUserKey
{
public:
	DSC_BIND_ATTR(m_nSequenceNumber, m_nAllocatedID);

public:
	ACE_UINT32 m_nSequenceNumber = 0; //校验用流水号
	ACE_UINT64 m_nAllocatedID = 0; //系统分配的 用户ID 或information-ID
};

void VBE::CVbeUserUtil::EncodeVbeUserKey(DSC::CDscShortBlob& outVbeUserKey, DSC::CDscShortBlob& inVbhUserKey, ACE_UINT32 inChannleID)
{
	char* buf;
	size_t bufLen;
	CVbeUserKey userKey(inVbhUserKey, inChannleID);

	DSC::Encode(userKey, buf, bufLen);

	outVbeUserKey.Set(buf, bufLen);
}

ACE_INT32 VBE::CVbeUserUtil::DecodeVbeUserKey(DSC::CDscShortBlob& outVbhUserKey, ACE_UINT32 &outChannleID, DSC::CDscShortBlob& inVbeUserKey)
{
	CVbeUserKey userKey(outVbhUserKey, outChannleID);

	return DSC::Decode(userKey, inVbeUserKey.c_str(), inVbeUserKey.size());
}

ACE_UINT64 VBE::CVbeUserUtil::GetHashKey(DSC::CDscShortBlob& inVbhUserKey)
{
	CVbhUserKey key;

	DSC::Decode(key, inVbhUserKey.c_str(), inVbhUserKey.size());

	return key.m_nAllocatedID;
}
