#include "crashdump.h"
#include "_cgo_export.h"

#define INITGUID
#include "guiddef.h"
DEFINE_GUID(IID_IDebugControl, 0x5182e668, 0x105e, 0x416e,
            0xad, 0x92, 0x24, 0xef, 0x80, 0x04, 0x24, 0xba);
/* 27fe5639-8407-4f47-8364-ee118fb08ac8 */
DEFINE_GUID(IID_IDebugClient, 0x27fe5639, 0x8407, 0x4f47,
            0x83, 0x64, 0xee, 0x11, 0x8f, 0xb0, 0x8a, 0xc8);

/* 4bf58045-d654-4c40-b0af-683090f356dc */
DEFINE_GUID(IID_IDebugOutputCallbacks, 0x4bf58045, 0xd654, 0x4c40,
            0xb0, 0xaf, 0x68, 0x30, 0x90, 0xf3, 0x56, 0xdc);

class StdioOutputCallbacks : public IDebugOutputCallbacks {
private:
    StdioOutputCallbacks();
    void * ctx;
public:
    StdioOutputCallbacks(void *ctx)
        : ctx(ctx)
    {};
    STDMETHOD(QueryInterface)(THIS_ _In_ REFIID ifid, _Out_ PVOID* iface);
    STDMETHOD_(ULONG, AddRef)(THIS);
    STDMETHOD_(ULONG, Release)(THIS);
    STDMETHOD(Output)(THIS_ IN ULONG Mask, IN PCSTR Text);
};
STDMETHODIMP
StdioOutputCallbacks::QueryInterface(THIS_ _In_ REFIID ifid, _Out_ PVOID* iface) {
    *iface = NULL;
    if (IsEqualIID(ifid, IID_IDebugOutputCallbacks)) {
        *iface = (IDebugOutputCallbacks*)this;
        AddRef();
        return S_OK;
    }
    else {
        return E_NOINTERFACE;
    }
}
STDMETHODIMP_(ULONG)
StdioOutputCallbacks::AddRef(THIS) { return 1; }
STDMETHODIMP_(ULONG)
StdioOutputCallbacks::Release(THIS) { return 0; }
STDMETHODIMP StdioOutputCallbacks::Output(THIS_ IN ULONG, IN PCSTR Text) {
    logLineCallback(this->ctx, Text);
    return S_OK;
}

int readCrashDump(char *fname, void *ctx)
{
    IDebugClient* g_Client;
    IDebugControl* g_Control;
    StdioOutputCallbacks g_OutputCb(ctx);
    DebugCreate(IID_IDebugClient, (void**)&g_Client);
    g_Client->QueryInterface(IID_IDebugControl, (void**)&g_Control);
    g_Client->SetOutputCallbacks(&g_OutputCb);
    g_Client->OpenDumpFile(fname);
    g_Control->WaitForEvent(0, INFINITE);
    g_Control->Execute(DEBUG_OUTCTL_THIS_CLIENT, "kb", DEBUG_EXECUTE_DEFAULT);

    g_Control->Release();
    g_Client->Release();
    return 0;
    
}