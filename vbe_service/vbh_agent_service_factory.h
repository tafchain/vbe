#ifndef _VBH_AGENT_SERVICE_FACTORY_H_2867567826245738371
#define _VBH_AGENT_SERVICE_FACTORY_H_2867567826245738371

#include "dsc/service/dsc_service_container.h"

#include "vbe/vbe_service/vbh_agent_service.h"


class PLUGIN_EXPORT CVbhAgentServiceFactory : public IDscServiceFactory
{
public:
	virtual CDscService* CreateDscService(void);

public:
	CVbhAgentService* m_pHas = nullptr;
};
#endif