#ifndef _VBE_COMMON_MSG_WRAPPER_H_10365718768910717
#define _VBE_COMMON_MSG_WRAPPER_H_10365718768910717

#include "vbe/vbe_common/vbe_common_def.h"
#include "vbh/common/vbh_encrypt_lib.h"
#include "dsc/codec/dsc_codec/dsc_codec.h"
#include "dsc/container/dsc_array.h"


namespace VBE {
	template<typename WARPPER_TYPE>
	ACE_INT32 EncryptWrapperMsg(WARPPER_TYPE& warpperData, const DSC::CDscShortBlob& envolopeKey, char*& outBuf, ACE_UINT32& outLen);
	template<typename WARPPER_TYPE>
	char* DecryptWrapperMsg(WARPPER_TYPE& warpperData, const DSC::CDscShortBlob& envolopeKey, char* data, ACE_UINT32 dataLen);

	class   CLoginCltVbeReqDataWrapper
	{
	public:
		
	VBE_EXPORT	CLoginCltVbeReqDataWrapper(DSC::CDscShortBlob& nonce);

	public:
		DSC_BIND_ATTR(m_nonce);

	public:
		DSC::CDscShortBlob& m_nonce;
	};

	class CLoginVbeCltRspDataWrapper
	{
	public:
		 VBE_EXPORT CLoginVbeCltRspDataWrapper(DSC::CDscShortBlob& nonce, ACE_UINT32& token);

	public:
		DSC_BIND_ATTR(m_nonce, m_token);

	public:
		DSC::CDscShortBlob& m_nonce;
		ACE_UINT32& m_token;
	};

	class CRegisterUserCltRegReqDataWrapper
	{
	public:
		  VBE_EXPORT CRegisterUserCltRegReqDataWrapper(DSC::CDscShortBlob& nonce, DSC::CDscShortBlob& userInfo, DSC::CDscShortBlob& m_serverCryptKey);

	public:
		DSC_BIND_ATTR(m_nonce, m_userInfo);

	public:
		DSC::CDscShortBlob& m_nonce;
		DSC::CDscShortBlob& m_userInfo;
		DSC::CDscShortBlob& m_serverCryptKey;

	};

	class CRegisterUserRegCltRspDataWrapper
	{
	public:
		  VBE_EXPORT CRegisterUserRegCltRspDataWrapper(DSC::CDscShortBlob& nonce, DSC::CDscShortBlob& userKey);

	public:
		DSC_BIND_ATTR(m_nonce, m_userKey);

	public:
		DSC::CDscShortBlob& m_nonce;
		DSC::CDscShortBlob& m_userKey;

	};

	class CTransferCltVbeReqDataWrapper
	{
	public:
		VBE_EXPORT CTransferCltVbeReqDataWrapper(DSC::CDscShortBlob& nonce, ACE_UINT32& nTotalCoin, DSC::CDscShortList<DSC::CDscShortBlob>& userKeyList,
			DSC::CDscShortList<ACE_UINT32>& coinList);
		
	public:
		DSC_BIND_ATTR(m_nonce, m_nTotalCoin, m_userKeyList, m_coinList);

	public:
		DSC::CDscShortBlob& m_nonce;
		ACE_UINT32 &m_nTotalCoin;
		DSC::CDscShortList<DSC::CDscShortBlob> &m_userKeyList;
		DSC::CDscShortList<ACE_UINT32> &m_coinList;
	};

	class CTransferVbeCltRspDataWrapper
	{
	public:
		VBE_EXPORT CTransferVbeCltRspDataWrapper(DSC::CDscShortBlob& nonce, DSC::CDscShortBlob& transKey);

	public:
		DSC_BIND_ATTR(m_nonce, m_transKey);

	public:
		DSC::CDscShortBlob& m_nonce;
		DSC::CDscShortBlob& m_transKey;
	};

	class CGetUserInfoCltVbeReqDataWrapper
	{
	public:
		VBE_EXPORT CGetUserInfoCltVbeReqDataWrapper(DSC::CDscShortBlob& nonce);

	public:
		DSC_BIND_ATTR(m_nonce);

	public:
		DSC::CDscShortBlob& m_nonce;
	};

	class CGetUserInfoVbeCltRspDataWrapper
	{
	public:
		VBE_EXPORT CGetUserInfoVbeCltRspDataWrapper(DSC::CDscShortBlob& nonce, DSC::CDscShortBlob& userinfo);

	public:
		DSC_BIND_ATTR(m_nonce, m_userinfo);

	public:
		DSC::CDscShortBlob& m_nonce;
		DSC::CDscShortBlob& m_userinfo;
	};

#include "vbe/vbe_common/vbe_common_msg_wrapper.inl"
}

#endif
