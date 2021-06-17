#include "vbe/vbe_client_service/vbe_client_service_plugin.h"


#include "dsc/plugin/dsc_service_factory.h"
#include "dsc/service/dsc_service_container.h"

#include "vbe/vbe_client_service/vbe_client_service.h"


ACE_INT32 CSdkClientServicePlugIn::OnInit(void)
{
	CDscServiceFactory<CVbeClientService> serviceFactory;
	ACE_INT32 nRet = ::RegistOneReactorDscService(&serviceFactory);

	if (nRet)
	{
		DSC_RUN_LOG_ERROR("regist user service regist failed");
	}
	else
	{
		DSC_RUN_LOG_FINE("regist user service regist successfully");
	}

	return nRet;
}

extern "C" PLUGIN_EXPORT void* CreateDscPlugin(void)
{
	CSdkClientServicePlugIn* pPlugIn = NULL;

	DSC_NEW(pPlugIn, CSdkClientServicePlugIn);

	return pPlugIn;
}
