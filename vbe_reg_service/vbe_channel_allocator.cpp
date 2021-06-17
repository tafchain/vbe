#include "vbe/vbe_reg_service/vbe_channel_allocator.h"

CVbeChannelAllocator::CVbeChannelAllocator()
{
}

CVbeChannelAllocator::~CVbeChannelAllocator()
{
}

ACE_INT32 CVbeChannelAllocator::Init()
{
	if (VBE::CVbeHlsRouter::Open())
	{
		return -1;
	}
}
