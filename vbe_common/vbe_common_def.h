#ifndef _VBE_COMMON_DEF_H_18501245610467
#define _VBE_COMMON_DEF_H_18501245610467

#ifdef WIN32
#ifdef DECLARE_VBE_EXPORT
#define VBE_EXPORT __declspec(dllexport)
#else
#define VBE_EXPORT __declspec(dllimport)
#endif
#else
#ifdef __GNUC__
#define VBE_EXPORT __attribute__ ((visibility("default")))
#else
#define VBE_EXPORT
#endif
#endif

namespace VBE
{
	enum __ERRORS
	{
		EN_OK_TYPE = 0,
		EN_USER_NOT_LOGIN_ERROR_TYPE,
		EN_PARAM_ERROR_TYPE,
		EN_DECRYPT_ERROR_TYPE,
		EN_NONCE_ERROR_TYPE,
		EN_SYSTEM_ERROR_TYPE,
		EN_NETWORK_ERROR_TYPE,
		EN_TIMEOUT_ERROR_TYPE,
		EN_LOCK_ERROR_TYPE,
	};


	enum 
	{
		EN_VBE_CLIENT_APP_TYPE = 301,
		EN_VBE_SERVICE_APP_TYPE = 311,
		EN_VBE_REG_SERVICE_APP_TYPE = 321,
	};
	// msg type
	enum 
	{
		EN_INIT_SDK_MSG = 301,
		EN_LOGIN_REQ_MSG,
		EN_LOGIN_RSP_MSG,
		EN_REGIST_USER_REQ_MSG,
		EN_REGIST_USER_RSP_MSG,
		EN_TRANSFER_REQ_MSG,
		EN_TRANSFER_RSP_MSG,
		EN_TRANSFER_HLS_REQ_MSG,
		EN_TRANSFER_HLS_RSP_MSG,
		EN_LOCK_USERS_REQ_MSG,
		EN_LOCK_USERS_RSP_MSG,
		EN_CHECK_USERS_REQ_MSG,
		EN_CHECK_USERS_RSP_MSG,
		EN_UNLOCK_USERS_REQ_MSG,
		EN_UNLOCK_USERS_RSP_MSG,
		EN_GET_USERINFO_REQ_MSG,
		EN_GET_USERINFO_RSP_MSG,

	};
	enum 
	{
		EN_VBE_CLIENT_SERVICE_TYPE = 301,
		EN_VBE_REG_SERVICE_TYPE,
		EN_VBE_SERVICE_TYPE,
		EN_VBE_SERVICE_CONTAINER_TYPE,
		EN_VBE_HLS_SERVICE_TYPE,
		EN_VBE_VBH_AGENT_SERVICE_TYPE,
	};
}



#endif
