#ifndef _VBE_REG_SERVICE_PLUGIN_H_5724567218843
#define _VBE_REG_SERVICE_PLUGIN_H_5724567218843

#include "dsc/plugin/i_dsc_plugin.h"
#include "dsc/service/dsc_service_container.h"

class CVbeRegServiceFactory : public IDscServiceFactory
{
public:
	virtual CDscService* CreateDscService(void);

public:
	CDscString m_strAddr;
	ACE_INT32 m_nPort;
	ACE_UINT16 m_nServiceID;

};

class CSdkClientServicePlugIn : public IDscPlugin
{
public:
	ACE_INT32 OnInit(void);
};

#endif
