#ifndef _VBE_HLS_ROUTER_H_78051378450146171
#define _VBE_HLS_ROUTER_H_78051378450146171

#include "vbe/vbe_common/vbe_common_def.h"

#include "dsc/dsc_msg.h"
#include "dsc/configure/dsc_configure.h"
#include "dsc/container/bare_hash_map.h"

namespace VBE {
	class VBE_EXPORT  CVbeHlsRouter
	{

	public:
		CVbeHlsRouter();
		virtual ~CVbeHlsRouter();

		//打开, 初始化
		ACE_INT32 Open(void);

		//获取特定channel 用户的 xcs地址
		ACE_INT32 GetHlsAddr(CDscMsg::CDscMsgAddr& addr, const ACE_UINT32 nChannelID);

	
	protected:
		class CDscAddr //在DSC系统中 地址 的 ID部分
		{
		public:
			ACE_INT16 m_nNodeID;
			ACE_INT16 m_nServiceID;

		public:
			ACE_UINT32 m_nKey = 0;
			CDscAddr* m_pPrev = NULL;
			CDscAddr* m_pNext = NULL;
		};

		using channel_map_dsc_addr_type = dsc_unordered_map_type(ACE_UINT32, CDscAddr*); //channel -> hls addr

	protected:
		channel_map_dsc_addr_type m_mapChannelMapHlsAddr;

	private:
		//加载 channel 和 tcs addr 的映射关系
		ACE_INT32 LoadChannelMapHlsAddr();
		void ClearChannelMap();

	};

}
#endif
