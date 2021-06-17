#include "vbe_rr_channel_allocator.h"

CVbeRrChannelAllocator::CVbeRrChannelAllocator()
{
}

CVbeRrChannelAllocator::~CVbeRrChannelAllocator()
{
}

ACE_INT32 CVbeRrChannelAllocator::Init()
{
	if (CVbeRrChannelAllocator::Init())
	{
		return -1;
	}

	m_iterator = m_mapChannelMapHlsAddr.begin();
}

ACE_UINT32 CVbeRrChannelAllocator::AllocChannel()
{
	if (m_iterator == m_mapChannelMapHlsAddr.end())
	{
		m_iterator = m_mapChannelMapHlsAddr.begin();
	}

	auto ch = m_iterator->first;

	m_iterator++;

	return ch;
}
