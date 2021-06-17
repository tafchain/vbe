#include "vbe/vbe_app/vbe_appmanager.h"

#include "dsc/dsc_comm_def.h"

#include "common/vbh_comm_func.h"
#include "common/vbh_encrypt_lib.h"


ACE_INT32 CVbeAppManager::OnInit()
{
	VBH::InitOpenSsl();
	DSC_FORWARD_CALL(CDscAppManager::OnInit());

	return 0;
}

ACE_INT32 CVbeAppManager::OnExit()
{
	DSC_FORWARD_CALL(CDscAppManager::OnExit());

	return 0;
}




