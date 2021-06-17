#ifndef _VBE_HLS_SERVICE_PLUGIN_H_81075860813745916
#define _VBE_HLS_SERVICE_PLUGIN_H_81075860813745916

#include "dsc/plugin/i_dsc_plugin.h"

class CVbeHlsServicePlugin : public IDscPlugin
{
public:
	CVbeHlsServicePlugin();

public:
	ACE_INT32 OnInit(void);

};


#endif
