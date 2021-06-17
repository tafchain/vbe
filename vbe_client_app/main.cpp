#include "vbe/vbe_client_sdk/vbe_client_sdk.h"

using namespace VBE_SDK;

static bool sReady = false;

class CVbeCallback : public IClientSdkMsgCallback
{
public:
	CVbeCallback () {}
	~CVbeCallback() {}
	virtual void OnReady(void) override {
		printf("OnReady callback\n");
		sReady = true;

	}
	virtual void OnAbnormal(void) override {
		printf("OnAbnormal callback\n");
	}
	virtual void OnExit(void) override {
		printf("OnExit callback\n");
	}
private:

};



int main(int argc, char* argv[])
{
	CVbeClientSdk vbeSdk;
	CVbeCallback callback;

	vbeSdk.Init(123, &callback);

	const char* str = "hiorgermioooqre";
	while (1)
	{
		Sleep(1000);
		if (sReady) {
			printf("RegisterUser");
			vbeSdk.Login(34, str, strlen(str) + 1, str, strlen(str) + 1);
			break;
		}
	}
	while (true)
	{
		Sleep(1000);
	}
	return 0;
}

