#ifndef _VBE_CHANNEL_CONTAINER_H_8501227202728
#define _VBE_CHANNEL_CONTAINER_H_8501227202728


#include "vbe/vbe_common/vbe_hls_router.h"

class CVbeChannelAllocator : public VBE::CVbeHlsRouter
{
public:
	CVbeChannelAllocator();
	virtual ~CVbeChannelAllocator();

	ACE_INT32 Init();

	// 各个分配器可实现不同的分配策略
	virtual ACE_UINT32 AllocChannel() = 0;
};





#endif
