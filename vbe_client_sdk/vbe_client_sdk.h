#ifndef _VBE_CLIENT_SDK_H_83107513465091478
#define _VBE_CLIENT_SDK_H_83107513465091478

#include "ace/Basic_Types.h"
#include "dsc/dsc_export.h"
#include "dsc/codec/codec_base/dsc_codec_base.h"

namespace VBE_SDK
{
	class CTransferReceiver
	{
	public:
		ACE_UINT32 m_nCoin;
		DSC::CDscShortBlob m_userKey;
	};

	class IClientSdkMsgCallback
	{
	public:
		virtual void OnReady(void) {}
		virtual void OnAbnormal(void) {}
		virtual void OnExit(void) {}
	public:
		virtual void OnRegisterUserResponse(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, DSC::CDscShortBlob* userKey = nullptr) {}
		virtual void OnLoginResponse(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, ACE_UINT32 token = 0){}
		virtual void OnTransferResponse(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, DSC::CDscShortBlob* transKey = nullptr){}
		virtual void OnGetUserInfoResponse(ACE_INT32 nReturnCode, ACE_UINT32 nRequestID, DSC::CDscShortBlob* userinfo = nullptr) {}
	};

	class PLUGIN_EXPORT CVbeClientSdk
	{
	public:
		CVbeClientSdk();
		~CVbeClientSdk();

		ACE_INT32 Init(const ACE_INT16 nAppID, IClientSdkMsgCallback* pCallBack);
		ACE_INT32 Deinit();

		ACE_INT32 RegisterUser(ACE_UINT32 nReqID, const char* userInfo, size_t nLen, const char* serverCryptKey, size_t nKeyLen);
		ACE_INT32 Login(ACE_UINT32 nReqID, const char* userKey, size_t nUserKeyLen, const char* cryptUserKey, size_t nCryptUserKeyLen);
		ACE_INT32 Transfer(ACE_UINT32 nReqID, ACE_UINT32 nToken, DSC::CDscShortList<CTransferReceiver> &lstReceiver);
		ACE_INT32 GetUserInfo(ACE_UINT32 nReqID, ACE_UINT32 nToken);

	private:
	};
}


#endif
