

template<typename WARPPER_TYPE>
inline ACE_INT32 EncryptWrapperMsg(WARPPER_TYPE& warpperData, const DSC::CDscShortBlob& envolopeKey, char*& outBuf, ACE_UINT32& outLen)
{
	char* encodeBuf = nullptr;
	size_t encodeBufLen = 0;
	char* pEncryptMsgBuf;
	int nEncryptMsgBufLen;

	DSC::Encode(warpperData, encodeBuf, encodeBufLen);

	pEncryptMsgBuf = VBH::vbhEncrypt((unsigned char*)envolopeKey.c_str(), nEncryptMsgBufLen, encodeBuf, encodeBufLen);

	DSC_THREAD_SIZE_FREE(encodeBuf, encodeBufLen);
	outBuf = pEncryptMsgBuf;
	outLen = nEncryptMsgBufLen;
	return 0;
}


template<typename WARPPER_TYPE>
char* DecryptWrapperMsg(WARPPER_TYPE& warpperData,const DSC::CDscShortBlob& envolopeKey, char* data, ACE_UINT32 dataLen)
{
	int nDecryptBufLen;
	char* pDecryptBuf = VBH::vbhDecrypt((const unsigned char*)envolopeKey.c_str(),
		nDecryptBufLen, data, dataLen);

	if (DSC_LIKELY(pDecryptBuf))
	{
		if (DSC::Decode(warpperData, pDecryptBuf, nDecryptBufLen))
		{
			//
			return nullptr;
		}

		return pDecryptBuf;
	}
	else
	{
		// 
	}

	return nullptr;
}

