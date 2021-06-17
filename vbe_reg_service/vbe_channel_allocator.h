#ifndef _VBE_CHANNEL_CONTAINER_H_8501227202728
#define _VBE_CHANNEL_CONTAINER_H_8501227202728


#include "vbe/vbe_common/vbe_hls_router.h"

class CVbeChannelAllocator : public VBE::CVbeHlsRouter
{
public:
	CVbeChannelAllocator();
	virtual ~CVbeChannelAllocator();

	ACE_INT32 Init();

	// ������������ʵ�ֲ�ͬ�ķ������
	virtual ACE_UINT32 AllocChannel() = 0;
};





#endif
