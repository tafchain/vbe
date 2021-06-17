#ifndef _VBE_CLIENT_SERVICE_PLUGIN_H_840513460134617
#define _VBE_CLIENT_SERVICE_PLUGIN_H_840513460134617

#include "dsc/plugin/i_dsc_plugin.h"

class CSdkClientServicePlugIn : public IDscPlugin
{
public:
	ACE_INT32 OnInit(void);
};

#endif
