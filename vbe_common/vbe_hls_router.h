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

		//��, ��ʼ��
		ACE_INT32 Open(void);

		//��ȡ�ض�channel �û��� xcs��ַ
		ACE_INT32 GetHlsAddr(CDscMsg::CDscMsgAddr& addr, const ACE_UINT32 nChannelID);

	
	protected:
		class CDscAddr //��DSCϵͳ�� ��ַ �� ID����
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
		//���� channel �� tcs addr ��ӳ���ϵ
		ACE_INT32 LoadChannelMapHlsAddr();
		void ClearChannelMap();

	};

}
#endif
