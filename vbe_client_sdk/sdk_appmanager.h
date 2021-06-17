#ifndef _VBE_CLIENT_SDK_APPMANAGER_H_80175184516
#define _VBE_CLIENT_SDK_APPMANAGER_H_80175184516

#include "dsc/dsc_app_mng.h"


namespace VBE_SDK
{
	class CSdkAppManager : public CDscAppManager
	{

	protected:
		virtual ACE_INT32 OnInit(void);
		virtual ACE_INT32 OnExit(void);
	};
}



#endif
