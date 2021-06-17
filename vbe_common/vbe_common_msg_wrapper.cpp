#include "vbe_common_msg_wrapper.h"

namespace VBE
{
	CRegisterUserCltRegReqDataWrapper::CRegisterUserCltRegReqDataWrapper(DSC::CDscShortBlob& nonce, DSC::CDscShortBlob& userInfo, DSC::CDscShortBlob& serverCryptKey)
		: m_nonce(nonce), m_userInfo(userInfo), m_serverCryptKey(serverCryptKey)
	{
	}
	CLoginCltVbeReqDataWrapper::CLoginCltVbeReqDataWrapper(DSC::CDscShortBlob& nonce)
		: m_nonce(nonce)
	{
	}
	CLoginVbeCltRspDataWrapper::CLoginVbeCltRspDataWrapper(DSC::CDscShortBlob& nonce, ACE_UINT32& token)
		: m_nonce(nonce), m_token(token)
	{
	}
	CRegisterUserRegCltRspDataWrapper::CRegisterUserRegCltRspDataWrapper(DSC::CDscShortBlob& nonce, DSC::CDscShortBlob& userKey)
		:m_nonce(nonce), m_userKey(userKey)
	{
	}
	CTransferCltVbeReqDataWrapper::CTransferCltVbeReqDataWrapper(DSC::CDscShortBlob& nonce, ACE_UINT32& nTotalCoin, DSC::CDscShortList<DSC::CDscShortBlob>& userKeyList, DSC::CDscShortList<ACE_UINT32>& coinList)
		:m_nonce(nonce), m_nTotalCoin(nTotalCoin), m_userKeyList(userKeyList), m_coinList(coinList)
	{
	}	
	CTransferVbeCltRspDataWrapper::CTransferVbeCltRspDataWrapper(DSC::CDscShortBlob& nonce, DSC::CDscShortBlob& transKey)
		:m_nonce(nonce), m_transKey(transKey)
	{
	}
	CGetUserInfoCltVbeReqDataWrapper::CGetUserInfoCltVbeReqDataWrapper(DSC::CDscShortBlob& nonce)
		:m_nonce(nonce)
	{
	}
	CGetUserInfoVbeCltRspDataWrapper::CGetUserInfoVbeCltRspDataWrapper(DSC::CDscShortBlob& nonce, DSC::CDscShortBlob& userinfo)
		:m_nonce(nonce), m_userinfo(userinfo)
	{
	}

}
