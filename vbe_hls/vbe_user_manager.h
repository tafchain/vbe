#ifndef _VBE_USER_MANAGER_H_80167160237423691
#define _VBE_USER_MANAGER_H_80167160237423691

#include "dsc/codec/dsc_codec/dsc_codec.h"
#include "dsc/service_timer/dsc_service_timer_handler.h"
#include "dsc/container/bare_hash_map.h"
#include "dsc/mem_mng/dsc_stl_type.h"
#include "dsc/storage/small_block_storage/small_block_storage.h"


class CVbeUserInfo
{
public:
	DSC_BIND_ATTR(m_nHashKey, m_nLockKey, m_bLocked);
public:
	ACE_UINT64 m_nHashKey;
	ACE_UINT32 m_nLockKey;
	bool m_bLocked = false;
};

class CVbeUserManager
{
public:
	ACE_INT32 Init();

public:
	bool LockUser(ACE_UINT64 nHashKey, ACE_UINT32 nLockKey);
	void UnlockUser(ACE_UINT64 nHashKey);
	bool CheckLock(ACE_UINT64 nHashKey, ACE_UINT32 nLockKey);
	void PutUserInfo(CVbeUserInfo& userinfo, ACE_UINT32 nCoin = 0);
	ACE_INT32 GetUserInfo(ACE_UINT64 nHashKey, CVbeUserInfo& userinfo);

	ACE_UINT32 AllocLockKey();

private:
	enum
	{
		EN_HASH_MAP_BITES  = 16
	};

	class CUserState
	{
	public:
		SBS::SbsRecord m_dbRecord;
		ACE_UINT32 m_nCoin;
	};

private:
	CUserState* GetUserState(ACE_UINT64 nHashKey);

private:
	using user_state_map_type = dsc_unordered_map_type(ACE_UINT64, CUserState*);

private:
	user_state_map_type m_mapUserState;

	ACE_UINT32 m_nLockKey;
	CSmallBlockStorage m_dbUserInfo;
};
















#endif




