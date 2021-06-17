#include "dsc/dsc_comm_def.h"

#include "vbe/vbe_client_sdk/sdk_appmanager.h"
#include "common/vbh_comm_func.h"
#include "common/vbh_encrypt_lib.h"

namespace VBE_SDK
{

	ACE_INT32 CSdkAppManager::OnInit()
	{
		VBH::InitOpenSsl();
		DSC_FORWARD_CALL(CDscAppManager::OnInit());

		return 0;
	}

	ACE_INT32 CSdkAppManager::OnExit()
	{
		DSC_FORWARD_CALL(CDscAppManager::OnExit());

		return 0;
	}

}
