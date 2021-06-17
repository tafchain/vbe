#ifndef _VBE_RR_CHANNEL_ALLOCATOR_H_80127027720112617
#define _VBE_RR_CHANNEL_ALLOCATOR_H_80127027720112617

#include "vbe/vbe_reg_service/vbe_channel_allocator.h"

// ÂÖÑ¯·ÖÅäÆ÷
class CVbeRrChannelAllocator : public CVbeChannelAllocator
{
public:
	CVbeRrChannelAllocator();
	virtual ~CVbeRrChannelAllocator();

	ACE_INT32 Init();

public:
	virtual ACE_UINT32 AllocChannel();

private:
	channel_map_dsc_addr_type::iterator m_iterator;
};



#endif
