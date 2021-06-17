#include "vbe/vbe_client_sdk/vbe_client_sdk.h"
#include "vbe/vbe_client_sdk/sdk_appmanager.h"
#include "vbe/vbe_common/vbe_common_def.h"
#include "vbe/vbe_common/vbe_common_msg.h"

#include <atomic>

#include "ace/Init_ACE.h"
#include "ace/Thread_Manager.h"
#include "ace/Event.h"
#include "ace/OS_NS_fcntl.h"
#include "ace/OS_NS_string.h"
#include "ace/OS_NS_sys_stat.h"

#include "dsc/mem_mng/dsc_allocator.h"
#include "dsc/dsc_app_mng.h"
#include "dsc/dsc_log.h"
#include "dsc/dispatcher/dsc_dispatcher_center.h"

namespace VBE_SDK
{
	ACE_INT32 SendVbeMessage(CDscMsg* pDscMsg)
	{
		ACE_ASSERT(pDscMsg);

		CDscMsg::CDscMsgAddr& rDesMsgAddr = pDscMsg->GetDesMsgAddr();

		if ((rDesMsgAddr.GetNodeType() == DSC::EN_INVALID_TYPE) || (rDesMsgAddr.GetServiceType() == DSC::EN_INVALID_TYPE))
		{
			return CDscDispatcherCenterDemon::instance()->SendDscMessageByMsgType(pDscMsg);
		}
		else
		{
			if ((rDesMsgAddr.GetNodeID() == DSC::EN_INVALID_ID) || (rDesMsgAddr.GetServiceID() == DSC::EN_INVALID_ID))
			{
				return CDscDispatcherCenterDemon::instance()->SendDscMessageByTaskType(pDscMsg);
			}
			else
			{
				return CDscDispatcherCenterDemon::instance()->SendDscMessageByAddr(pDscMsg);
			}
		}
	}

	template<typename TYPE>
	CDscMsg* GetDscMsg(TYPE& t, const CDscMsg::CDscMsgAddr& rAddress, const ACE_UINT16 nMessageType)
	{
		CDscEncodeState codeStateControl;

		DSC::GetSize(t, codeStateControl);

#ifdef DONNT_USING_MEMORY_POOL
		CDscMsg* pDscMsg = DSC::NewDscMsg(codeStateControl.GetSize());
#else
		CDscMsg* pDscMsg = CDscMsgAllocatorDemon::instance()->allocate(codeStateControl.GetSize());
#endif
		if (DSC_LIKELY(pDscMsg))
		{
			codeStateControl.SetBuffer(pDscMsg->GetMessageBodyPtr());

			t.Bind(codeStateControl);

			pDscMsg->SetSrcNodeType(CDscAppManager::m_nNodeType);
			pDscMsg->SetSrcNodeID(CDscAppManager::m_nNodeID);

			pDscMsg->SetDesMsgAddr(rAddress);
			pDscMsg->SetMsgType(nMessageType);
		}

		return pDscMsg;
	}

	template<typename TYPE>
	ACE_INT32 SendVbeMessage(TYPE& t, const ACE_UINT16 nMessageType, const CDscMsg::CDscMsgAddr& rAddress)
	{
		CDscMsg* pDscMsg = GetDscMsg(t, rAddress, nMessageType);
		if (DSC_LIKELY(pDscMsg))
		{
			if (DSC_UNLIKELY(SendVbeMessage(pDscMsg)))
			{
				DSC_RUN_LOG_WARNING("send dsc message failed, msg type:%d", pDscMsg->GetMsgType());
#ifdef DONNT_USING_MEMORY_POOL
				DSC::FreeDscMsg(pDscMsg);
#else
				CDscMsgAllocatorDemon::instance()->deallocate(pDscMsg);
#endif

				return -1;
			}
			else
			{
				return 0;
			}
		}

		return -1;
	}

	template<typename TYPE>
	inline ACE_INT32 SendVbeMessage(TYPE& t, const CDscMsg::CDscMsgAddr& rAddress)
	{
		return SendVbeMessage(t, TYPE::EN_MSG_ID, rAddress);
	}

	template<typename TYPE>
	ACE_INT32 SendSdkServiceMessage(TYPE& t)
	{
		CDscMsg::CDscMsgAddr addr;

		addr.SetNodeType(CDscAppManager::m_nNodeType);
		addr.SetNodeID(CDscAppManager::m_nNodeID);
		addr.SetServiceType(VBE::EN_VBE_CLIENT_SERVICE_TYPE);
		addr.SetServiceID(1);

		return SendVbeMessage(t, addr);
	}


	class CInitThreadParam
	{
	public:
		ACE_INT16 m_nAppType;
		ACE_INT16 m_nAppID;
		ACE_Event m_event;
	};

	std::atomic_flag s_lock = ATOMIC_FLAG_INIT;
	bool s_bInited = false;

	CVbeClientSdk::CVbeClientSdk()
	{
	}

	CVbeClientSdk::~CVbeClientSdk()
	{
	}

	ACE_THR_FUNC_RETURN ThreadFunction(void* para)
	{
		InitThreadAllocator();
		CSdkAppManager* pAppManager = NULL;

		DSC_NEW(pAppManager, CSdkAppManager);

		CInitThreadParam* pParam = (CInitThreadParam*)para;

		ACE_TCHAR* argv[3] = { (ACE_TCHAR*)"vbe_sdk", (ACE_TCHAR*)"-h" };

		pAppManager->SetNodeType(pParam->m_nAppType);
		pAppManager->SetNodeID(pParam->m_nAppID);
		argv[2] = getenv("WORK_ROOT");
		if (!argv[2])
		{
			ACE_OS::printf("Please check the setting of 'WORK_ROOT'\n");
			DSC_DELETE(pAppManager);

			pParam->m_nAppID = -1;
			pParam->m_event.signal();

			return 0;
		}

		if (pAppManager->Init(3, argv))
		{
			ACE_OS::printf("app init failed please check log\n");
			pAppManager->Exit();
			DSC_DELETE(pAppManager);

			pParam->m_nAppID = -1;
			pParam->m_event.signal();

			return 0;
		}

		pParam->m_event.signal();
		pAppManager->Run_Loop();

		DSC_DELETE(pAppManager);

		DeleteThreadAllocator();

		return 0;
	}

	ACE_INT32 CVbeClientSdk::Init(const ACE_INT16 nAppID, IClientSdkMsgCallback* pCallBack)
	{
		while (s_lock.test_and_set(std::memory_order_acquire));

		if (s_bInited)
		{//重复调用
			s_lock.clear(std::memory_order_release);

			return 0;
		}
		else
		{
			s_bInited = true;
			s_lock.clear(std::memory_order_release);
		}

		InitThreadAllocator();
		ACE::init();

		CInitThreadParam param;

		param.m_nAppType = VBE::EN_VBE_CLIENT_SERVICE_TYPE;
		param.m_nAppID = nAppID;

		//创建交易核心客户端线程
		if (-1 != ACE_Thread_Manager::instance()->spawn(ThreadFunction, &param, THR_NEW_LWP | THR_DETACHED))
		{
			param.m_event.wait();
			if (param.m_nAppID == nAppID)
			{
				VBE::CInitSdk init;

				init.m_pCallBack = pCallBack;
				SendSdkServiceMessage(init);

				return 0;
			}
			else
			{
				return -1;
			}
		}

		return -1;
	}

	ACE_INT32 CVbeClientSdk::Deinit()
	{
		CDscAppManager::Instance()->SetAppExited();
		return 0;
	}

	ACE_INT32 CVbeClientSdk::RegisterUser(ACE_UINT32 nReqID, const char* userInfo, size_t nLen, const char* serverCryptKey, size_t nKeyLen)
	{
		VBE::CRegisterUserApiCltReq req;
		
		req.m_nSrcRequestID = nReqID;
		req.m_userInfo.Set(const_cast<char*>(userInfo), nLen);
		req.m_serverCryptKey.Set(const_cast<char*>(serverCryptKey), nKeyLen);

		return SendSdkServiceMessage(req);
	}

	ACE_INT32 CVbeClientSdk::Login(ACE_UINT32 nReqID, const char* userKey, size_t nUserKeyLen, const char* cryptUserKey, size_t nCryptUserKeyLen)
	{
		VBE::CLoginApiCltReq req;

		req.m_nSrcRequestID = nReqID;
		req.m_userKey.Set(const_cast<char*>(userKey), nUserKeyLen);
		req.m_cryptUserKey.Set(const_cast<char*>(cryptUserKey), nCryptUserKeyLen);

		return SendSdkServiceMessage(req);
	}

	ACE_INT32 CVbeClientSdk::Transfer(ACE_UINT32 nReqID, ACE_UINT32 nToken, DSC::CDscShortList<CTransferReceiver> &lstReceiver)
	{
		VBE::CTransferApiCltReq req;
		
		req.m_nSrcRequestID = nReqID;
		req.m_nToken = nToken;
		req.m_nTotalCoin = 0;

		for (auto &receiver: lstReceiver)
		{
			req.m_coinList.push_back(receiver.m_nCoin);
			req.m_userKeyList.push_back(receiver.m_userKey);
			req.m_nTotalCoin += receiver.m_nCoin;
		}

		return SendSdkServiceMessage(req);
	}

	ACE_INT32 CVbeClientSdk::GetUserInfo(ACE_UINT32 nReqID, ACE_UINT32 nToken)
	{
		VBE::CGetUserInfoApiCltReq req;

		req.m_nSrcRequestID = nReqID;
		req.m_nToken = nToken;

		return SendSdkServiceMessage(req);
	}
}
