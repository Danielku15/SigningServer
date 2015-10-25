#include "Stdafx.h"
#include "mssign32.h"

HMODULE MsSign32::_hMsSignDll = nullptr;
SignerSignPtr MsSign32::SignerSign = nullptr;
SignerSignExPtr MsSign32::SignerExSign = nullptr;
SignerFreeSignerContextPtr MsSign32::SignerFreeSignerContext = nullptr;
SignerTimeStampPtr MsSign32::SignerTimeStamp = nullptr;

HRESULT MsSign32::Init()
{
	_hMsSignDll = LoadLibrary(L"mssign32.dll");
	if (!_hMsSignDll)
	{
		return GetLastError();
	}

	SignerSign = (SignerSignPtr)GetProcAddress(_hMsSignDll, "SignerSign");
	if (!SignerSign)
	{
		return GetLastError();
	}
	SignerExSign = (SignerSignExPtr)GetProcAddress(_hMsSignDll, "SignerSignEx");
	if (!SignerExSign)
	{
		return GetLastError();
	}

	SignerFreeSignerContext = (SignerFreeSignerContextPtr)GetProcAddress(_hMsSignDll, "SignerFreeSignerContext");
	if (!SignerFreeSignerContext)
	{
		return GetLastError();
	}

	SignerTimeStamp = (SignerTimeStampPtr)GetProcAddress(_hMsSignDll, "SignerTimeStamp");
	if (!SignerTimeStamp)
	{
		return GetLastError();
	}

	return ERROR_SUCCESS;
}