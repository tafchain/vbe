#include "ace/OS_main.h"
#include "ace/OS_NS_stdio.h"

#include "vbe/vbe_app/vbe_appmanager.h"
#include "vbe/vbe_common/vbe_common_def.h"

int ACE_TMAIN(int argc, ACE_TCHAR* argv[])
{
	CVbeAppManager* pVbeAppManager = ::new(std::nothrow) CVbeAppManager;
	if (!pVbeAppManager)
	{
		ACE_OS::printf("failed to new VbeAppManager!");

		return -1;
	}

	pVbeAppManager->SetNodeType(VBE::EN_VBE_SERVICE_APP_TYPE);
	if (pVbeAppManager->Init(argc, argv))
	{
		ACE_OS::printf("VbeAppManager init failed, now exit!\n");
		pVbeAppManager->Exit();
		delete pVbeAppManager;

		return -1;
	}

	ACE_OS::printf("VbeAppManager init succeed, running...\n");
	pVbeAppManager->Run_Loop();
	delete pVbeAppManager;
	ACE_OS::printf("VbeAppManager terminated!\n");

	return 0;
}