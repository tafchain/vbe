#ifndef _VBE_SERVICE_PLUGIN_H_028460275657
#define _VBE_SERVICE_PLUGIN_H_028460275657

#include "vbe/vbe_service/vbe_service.h"

#include "dsc/plugin/i_dsc_plugin.h"
#include "dsc/service/dsc_service_container.h"

class CVbeServiceFactory : public IDscServiceFactory
{
public:
	virtual CDscService* CreateDscService(void);

public:

	CVbeService* m_vbeService;

};

class CSdkClientServicePlugIn : public IDscPlugin
{
public:
	ACE_INT32 OnInit(void);
};

#endif

