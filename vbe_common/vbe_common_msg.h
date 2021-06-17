#ifndef _VBE_COMMON_MSG_H_81045682375601561236
#define _VBE_COMMON_MSG_H_81045682375601561236

#include "vbe/vbe_common/vbe_common_def.h"

#include "dsc/codec/dsc_codec/dsc_codec.h"

namespace VBE
{
	class CInitSdk
	{
	public:
		enum
		{
			EN_MSG_ID = VBE::EN_INIT_SDK_MSG
		};

	public:
		DSC_BIND_ATTR(m_pCallBack);

	public:
		void* m_pCallBack = NULL;
	};

	class CLoginApiCltReq
	{
	public:
		enum
		{
			EN_MSG_ID = VBE::EN_LOGIN_REQ_MSG
		};

	public:
		DSC_BIND_ATTR(m_nSrcRequestID, m_userKey, m_cryptUserKey);

	public:
		ACE_UINT32 m_nSrcRequestID;
		DSC::CDscShortBlob m_userKey;
		DSC::CDscShortBlob m_cryptUserKey;
	};

	class CLoginCltVbeReq
	{
	public:
		enum
		{
			EN_MSG_ID = VBE::EN_LOGIN_REQ_MSG
		};

	public:
		DSC_BIND_ATTR(m_nSrcRequestID, m_userKey, m_data);

	public:
		ACE_UINT32 m_nSrcRequestID;
		DSC::CDscShortBlob m_userKey;
		DSC::CDscShortBlob m_data; // nonce
	};

	class CLoginVbeCltRsp
	{
	public:
		enum
		{
			EN_MSG_ID = VBE::EN_LOGIN_RSP_MSG
		};

	public:
		DSC_BIND_ATTR(m_nReturnCode, m_nSrcRequestID, m_data);

	public:
		ACE_INT32 m_nReturnCode;
		ACE_UINT32 m_nSrcRequestID;
		DSC::CDscShortBlob m_data; // nonce+token
	};

	class CRegisterUserApiCltReq
	{
	public:
		enum
		{
			EN_MSG_ID = VBE::EN_REGIST_USER_REQ_MSG
		};

	public:
		DSC_BIND_ATTR(m_nSrcRequestID, m_userInfo, m_serverCryptKey);

	public:
		ACE_UINT32 m_nSrcRequestID;
		DSC::CDscShortBlob m_userInfo;
		DSC::CDscShortBlob m_serverCryptKey;
	};

	class CRegisterUserCltRegReq
	{
	public:
		enum
		{
			EN_MSG_ID = VBE::EN_REGIST_USER_REQ_MSG
		};

	public:
		DSC_BIND_ATTR(m_nSrcRequestID, m_data);

	public:
		ACE_UINT32 m_nSrcRequestID;
		DSC::CDscShortBlob m_data; // nonce+userinfo
	};

	class CRegisterUserRegHlsReq
	{
	public:
		enum
		{
			EN_MSG_ID = VBE::EN_REGIST_USER_REQ_MSG
		};

	public:
		DSC_BIND_ATTR(m_nSrcRequestID, m_userInfo);

	public:
		ACE_UINT32 m_nSrcRequestID;
		DSC::CDscShortBlob m_userInfo; 
		DSC::CDscShortBlob m_serverCryptKey;
	};

	class CRegisterUserHlsRegRsp
	{
	public:
		enum
		{
			EN_MSG_ID = VBE::EN_REGIST_USER_RSP_MSG
		};

	public:
		DSC_BIND_ATTR(m_nReturnCode, m_nSrcRequestID, m_userKey);

	public:
		ACE_INT32 m_nReturnCode;
		ACE_UINT32 m_nSrcRequestID;
		DSC::CDscShortBlob m_userKey;
	};

	class CRegisterUserRegCltRsp
	{
	public:
		enum
		{
			EN_MSG_ID = VBE::EN_REGIST_USER_RSP_MSG
		};

	public:
		DSC_BIND_ATTR(m_nReturnCode, m_nSrcRequestID, m_data);
	public:
		ACE_INT32 m_nReturnCode;
		ACE_UINT32 m_nSrcRequestID;
		DSC::CDscShortBlob m_data; // nonce + userkey + cryptUserKey
	};

	class CCheckUsersVbeHlsReq
	{
	public:
		enum
		{
			EN_MSG_ID = VBE::EN_CHECK_USERS_REQ_MSG
		};

	public:
		DSC_BIND_ATTR(m_nSrcRequestID, m_lstUserKey);

	public:
		ACE_UINT32 m_nSrcRequestID;
		DSC::CDscShortList<DSC::CDscShortBlob> m_lstUserKey;
	};
	class CCheckUsersHlsVbeRsp
	{
	public:
		enum
		{
			EN_MSG_ID = VBE::EN_CHECK_USERS_RSP_MSG
		};

	public:
		DSC_BIND_ATTR(m_nReturnCode, m_nSrcRequestID);

	public:
		ACE_INT32 m_nReturnCode;
		ACE_UINT32 m_nSrcRequestID;
	};

	class CLockUsersVbeHlsReq
	{
	public:
		enum
		{
			EN_MSG_ID = VBE::EN_LOCK_USERS_REQ_MSG
		};

	public:
		DSC_BIND_ATTR(m_nSrcRequestID, m_userKeyList);

	public:
		ACE_UINT32 m_nSrcRequestID;
		DSC::CDscShortList<DSC::CDscShortBlob> m_userKeyList;
	};
	

	class CLockUsersHlsVbeRsp
	{
	public:
		enum
		{
			EN_MSG_ID = VBE::EN_LOCK_USERS_RSP_MSG
		};

	public:
		DSC_BIND_ATTR(m_nReturnCode, m_nSrcRequestID, m_nLockKey);

	public:
		ACE_INT32 m_nReturnCode;
		ACE_UINT32 m_nSrcRequestID;
		ACE_UINT32 m_nLockKey;
	};

	class CUnlockUsersVbeHlsReq
	{
	public:
		enum
		{
			EN_MSG_ID = VBE::EN_UNLOCK_USERS_REQ_MSG
		};

	public:
		DSC_BIND_ATTR(m_nSrcRequestID, m_nLockKey, m_userKeyList);

	public:
		ACE_UINT32 m_nSrcRequestID;
		ACE_UINT32 m_nLockKey;
		DSC::CDscShortList<DSC::CDscShortBlob> m_userKeyList;
	};

	class CUnlockUsersHlsVbeRsp
	{
	public:
		enum
		{
			EN_MSG_ID = VBE::EN_UNLOCK_USERS_RSP_MSG
		};

	public:
		DSC_BIND_ATTR(m_nReturnCode,m_nSrcRequestID);

	public:
		ACE_INT32 m_nReturnCode;
		ACE_UINT32 m_nSrcRequestID;
	};

	class CTransferApiCltReq
	{
	public:
		enum
		{
			EN_MSG_ID = VBE::EN_TRANSFER_REQ_MSG
		};

	public:
		DSC_BIND_ATTR(m_nSrcRequestID, m_nToken, m_nTotalCoin, m_userKeyList, m_coinList);

	public:
		ACE_UINT32 m_nSrcRequestID;
		ACE_UINT32 m_nToken;
		ACE_UINT32 m_nTotalCoin;
		DSC::CDscShortList<DSC::CDscShortBlob> m_userKeyList;
		DSC::CDscShortList<ACE_UINT32> m_coinList;
	};

	class CTransferCltVbeReq
	{
	public:
		enum
		{
			EN_MSG_ID = VBE::EN_TRANSFER_REQ_MSG
		};

	public:
		DSC_BIND_ATTR(m_nSrcRequestID, m_nToken, m_data);

	public:
		ACE_UINT32 m_nSrcRequestID;
		ACE_UINT32 m_nToken;
		DSC::CDscShortBlob m_data; // nonce + total coin + user key list + coin list
	};

	class CTransferVbeCltRsp
	{
	public:
		enum
		{
			EN_MSG_ID = VBE::EN_TRANSFER_RSP_MSG
		};

	public:
		DSC_BIND_ATTR(m_nReturnCode,m_nSrcRequestID, m_data);

	public:
		ACE_INT32 m_nReturnCode;
		ACE_UINT32 m_nSrcRequestID;
		DSC::CDscShortBlob m_data; // nonce + trans key
	};

	class CTransferVbeHlsReq
	{
	public:
		enum
		{
			EN_MSG_ID = VBE::EN_TRANSFER_REQ_MSG
		};

	public:
		DSC_BIND_ATTR(m_bMain,m_nSrcRequestID, m_sponsorUserKey, m_propose);
	public:
		bool m_bMain;
		ACE_UINT32 m_nSrcRequestID;
		DSC::CDscShortBlob m_sponsorUserKey;
		DSC::CDscShortBlob m_propose;
	};

	class CTransferHlsVbeRsp
	{
	public:
		enum
		{
			EN_MSG_ID = VBE::EN_TRANSFER_RSP_MSG
		};

	public:
		DSC_BIND_ATTR(m_nReturnCode, m_nSrcRequestID, m_nChannelID, m_transKey);

	public:
		ACE_INT32 m_nReturnCode;
		ACE_UINT32 m_nSrcRequestID;
		ACE_UINT32 m_nChannelID;
		DSC::CDscShortBlob m_transKey;
	};

	class CTransferHlsHlsReq
	{
	public:
		enum
		{
			EN_MSG_ID = VBE::EN_TRANSFER_HLS_REQ_MSG
		};

	public:
		DSC_BIND_ATTR(m_nSrcRequestID, m_propose);
	public:
		ACE_UINT32 m_nSrcRequestID;
		DSC::CDscShortBlob m_propose;
	};

	class CTransferHlsHlsRsp
	{
	public:
		enum
		{
			EN_MSG_ID = VBE::EN_TRANSFER_HLS_RSP_MSG
		};

	public:
		DSC_BIND_ATTR(m_nReturnCode, m_nSrcRequestID);
	public:
		ACE_INT32 m_nReturnCode;
		ACE_UINT32 m_nSrcRequestID;
	};

	class CGetUserInfoApiCltReq
	{
	public:
		enum
		{
			EN_MSG_ID = VBE::EN_GET_USERINFO_REQ_MSG
		};

	public:
		DSC_BIND_ATTR(m_nSrcRequestID, m_nToken);

	public:
		ACE_UINT32 m_nSrcRequestID;
		ACE_UINT32 m_nToken;
	};

	class CGetUserInfoCltVbeReq
	{
	public:
		enum
		{
			EN_MSG_ID = VBE::EN_GET_USERINFO_REQ_MSG
		};

	public:
		DSC_BIND_ATTR(m_nSrcRequestID, m_nToken, m_data);

	public:
		ACE_UINT32 m_nSrcRequestID;
		ACE_UINT32 m_nToken;
		DSC::CDscShortBlob m_data; // nonce
	};

	class CGetUserInfoVbeCltRsp
	{
	public:
		enum
		{
			EN_MSG_ID = VBE::EN_GET_USERINFO_REQ_MSG
		};

	public:
		DSC_BIND_ATTR(m_nReturnCode, m_nSrcRequestID, m_data);

	public:
		ACE_INT32 m_nReturnCode;
		ACE_UINT32 m_nSrcRequestID;
		DSC::CDscShortBlob m_data; // nonce+userinfo
	};
}






#endif // !_VBE_COMMON_MSG_H_81045682375601561236
