#include "dsc/codec/dsc_codec/dsc_codec.h"
#include "dsc/dsc_msg_allocator.h"
#include "dsc/dsc_log.h"


	template<typename TYPE>
	CDscMsg* VBE_SDK::CVbeClientSdk::GetDscMsg(TYPE& t, const CDscMsg::CDscMsgAddr& rAddress, const ACE_UINT16 nMessageType)
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
	ACE_INT32 VBE_SDK::CVbeClientSdk::SendVbeMessage(TYPE& t, const ACE_UINT16 nMessageType, const CDscMsg::CDscMsgAddr& rAddress)
	{
		CDscMsg* pDscMsg = VBH_SDK::GetDscMsg(t, rAddress, nMessageType);
		if (DSC_LIKELY(pDscMsg))
		{
			if (DSC_UNLIKELY(VBH_SDK::SendVbhMessage(pDscMsg)))
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
	inline ACE_INT32 VBE_SDK::CVbeClientSdk::SendVbeMessage(TYPE& t, const CDscMsg::CDscMsgAddr& rAddress)
	{
		return CVbeClientSdk::SendVbhMessage(t, TYPE::EN_MSG_ID, rAddress);
	}
