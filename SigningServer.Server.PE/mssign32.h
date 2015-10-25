#pragma once

//-----------------------------------------------------------------------------
// This header file was assembled from MSDN content.
//
// Jeff Fitzsimons, 9/2008.
//-----------------------------------------------------------------------------
// http://www.curlybrace.com/projects/Authenticode/mssign32.h (2015-10-23)

#include <windows.h>
#include <wincrypt.h>

//-----------------------------------------------------------------------------
// Structures and constants.
//-----------------------------------------------------------------------------

const DWORD SPC_EXC_PE_PAGE_HASHES_FLAG = 0x10;     // Unsupported on Windows Server 2k3, XP, and 2k.
const DWORD SPC_INC_PE_IMPORT_ADDR_TABLE_FLAG = 0x20;     // Unsupported.
const DWORD SPC_INC_PE_DEBUG_INFO_FLAG = 0x40;     // Unsupported.
const DWORD SPC_INC_PE_RESOURCES_FLAG = 0x80;     // Unsupported.
const DWORD SPC_INC_PE_PAGE_HASHES_FLAG = 0x100;    // Unsupported on Windows Server 2k3, XP, and 2k.

typedef struct _SIGNER_FILE_INFO
{
	DWORD cbSize;
	LPCWSTR pwszFileName;
	HANDLE hFile;
} SIGNER_FILE_INFO, *PSIGNER_FILE_INFO;

typedef struct _SIGNER_BLOB_INFO
{
	DWORD cbSize;
	GUID *pGuidSubject;
	DWORD cbBlob;
	BYTE *pbBlob;
	LPCWSTR pwszDisplayName;
} SIGNER_BLOB_INFO, *PSIGNER_BLOB_INFO;

const DWORD SIGNER_SUBJECT_BLOB = 0x2;      // The subject is a BLOB.
const DWORD SIGNER_SUBJECT_FILE = 0x1;      // The subject is a file.

typedef struct _SIGNER_SUBJECT_INFO
{
	DWORD cbSize;
	DWORD *pdwIndex;            // Reserved.  Must be zero.
	DWORD dwSubjectChoice;
	union
	{
		SIGNER_FILE_INFO *pSignerFileInfo;
		SIGNER_BLOB_INFO *pSignerBlobInfo;
	};
} SIGNER_SUBJECT_INFO, *PSIGNER_SUBJECT_INFO;

typedef struct _SIGNER_CERT_STORE_INFO
{
	DWORD cbSize;
	PCCERT_CONTEXT pSigningCert;
	DWORD dwCertPolicy;
	HCERTSTORE hCertStore;
} SIGNER_CERT_STORE_INFO, *PSIGNER_CERT_STORE_INFO;

const DWORD SIGNER_CERT_POLICY_STORE = 1;
const DWORD SIGNER_CERT_POLICY_CHAIN = 2;
const DWORD SIGNER_CERT_POLICY_CHAIN_NO_ROOT = 8;

typedef struct _SIGNER_SPC_CHAIN_INFO
{
	DWORD cbSize;
	LPCWSTR pwszSpcFile;
	DWORD dwCertPolicy;
	HCERTSTORE hCertStore;
} SIGNER_SPC_CHAIN_INFO, *PSIGNER_SPC_CHAIN_INFO;

const DWORD SIGNER_CERT_SPC_FILE = 1;
const DWORD SIGNER_CERT_STORE = 2;
const DWORD SIGNER_CERT_SPC_CHAIN = 3;

typedef struct _SIGNER_CERT
{
	DWORD cbSize;
	DWORD dwCertChoice;
	union
	{
		LPCWSTR pwszSpcFile;
		SIGNER_CERT_STORE_INFO *pCertStoreInfo;
		SIGNER_SPC_CHAIN_INFO *pSpcChainInfo;
	};
	HWND hwnd;
} SIGNER_CERT, *PSIGNER_CERT;

typedef struct _SIGNER_ATTR_AUTHCODE
{
	DWORD cbSize;
	BOOL fCommercial;
	BOOL fIndividual;
	LPCWSTR pwszName;
	LPCWSTR pwszInfo;
} SIGNER_ATTR_AUTHCODE, *PSIGNER_ATTR_AUTHCODE;

const DWORD SIGNER_AUTHCODE_ATTR = 1;    // Signature has Authenticode attributes.
const DWORD SIGNER_NO_ATTR = 0;    // Signature does not have Authenticode attributes.

typedef struct _SIGNER_SIGNATURE_INFO
{
	DWORD cbSize;
	ALG_ID algidHash;                       // Defined in WinCrypt.h
	DWORD dwAttrChoice;
	union
	{
		SIGNER_ATTR_AUTHCODE *pAttrAuthcode;
	};
	PCRYPT_ATTRIBUTES psAuthenticated;
	PCRYPT_ATTRIBUTES psUnauthenticated;
} SIGNER_SIGNATURE_INFO, *PSIGNER_SIGNATURE_INFO;

const DWORD PVK_TYPE_FILE_NAME = 0x1;
const DWORD PVK_TYPE_KEYCONTAINER = 0x2;

typedef struct _SIGNER_PROVIDER_INFO {
	DWORD cbSize;
	LPCWSTR pwszProviderName;
	DWORD dwProviderType;
	DWORD dwKeySpec;
	DWORD dwPvkChoice;
	union
	{
		LPWSTR pwszPvkFileName;
		LPWSTR pwszKeyContainer;
	};
} SIGNER_PROVIDER_INFO, *PSIGNER_PROVIDER_INFO;

typedef struct _SIGNER_CONTEXT {
	DWORD cbSize;
	DWORD cbBlob;
	BYTE *pbBlob;
} SIGNER_CONTEXT, *PSIGNER_CONTEXT;

//-----------------------------------------------------------------------------
// Function declarations.
//
// Each function is declared normally, as in MSDN documentation, and is also
// provided as a function pointer typedef.  Use the function pointer typedef
// with LoadLibrary/GetProcAddress in order to dynamically call the functions
// at runtime.
//
// Example:
//    SignerSignPtr pSignerSign = 
//        (SignerSignPtr)GetProcAddress(hModule, "SignerSign");
//-----------------------------------------------------------------------------

HRESULT WINAPI SignerSign(
	__in      SIGNER_SUBJECT_INFO *pSubjectInfo,
	__in      SIGNER_CERT *pSignerCert,
	__in      SIGNER_SIGNATURE_INFO *pSignatureInfo,
	__in_opt  SIGNER_PROVIDER_INFO *pProviderInfo,
	__in_opt  LPCWSTR pwszHttpTimeStamp,
	__in_opt  PCRYPT_ATTRIBUTES psRequest,
	__in_opt  LPVOID pSipData
	);

typedef HRESULT(WINAPI *SignerSignPtr)(
	__in      SIGNER_SUBJECT_INFO *pSubjectInfo,
	__in      SIGNER_CERT *pSignerCert,
	__in      SIGNER_SIGNATURE_INFO *pSignatureInfo,
	__in_opt  SIGNER_PROVIDER_INFO *pProviderInfo,
	__in_opt  LPCWSTR pwszHttpTimeStamp,
	__in_opt  PCRYPT_ATTRIBUTES psRequest,
	__in_opt  LPVOID pSipData
	);

HRESULT WINAPI SignerSignEx(
	__in      DWORD dwFlags,
	__in      SIGNER_SUBJECT_INFO *pSubjectInfo,
	__in      SIGNER_CERT *pSignerCert,
	__in      SIGNER_SIGNATURE_INFO *pSignatureInfo,
	__in_opt  SIGNER_PROVIDER_INFO *pProviderInfo,
	__in_opt  LPCWSTR pwszHttpTimeStamp,
	__in_opt  PCRYPT_ATTRIBUTES psRequest,
	__in_opt  LPVOID pSipData,
	__out     SIGNER_CONTEXT **ppSignerContext
	);

typedef HRESULT(WINAPI *SignerSignExPtr)(
	__in      DWORD dwFlags,
	__in      SIGNER_SUBJECT_INFO *pSubjectInfo,
	__in      SIGNER_CERT *pSignerCert,
	__in      SIGNER_SIGNATURE_INFO *pSignatureInfo,
	__in_opt  SIGNER_PROVIDER_INFO *pProviderInfo,
	__in_opt  LPCWSTR pwszHttpTimeStamp,
	__in_opt  PCRYPT_ATTRIBUTES psRequest,
	__in_opt  LPVOID pSipData,
	__out     SIGNER_CONTEXT **ppSignerContext
	);

HRESULT WINAPI SignerFreeSignerContext(
	__in  SIGNER_CONTEXT *pSignerContext
	);

typedef HRESULT(WINAPI *SignerFreeSignerContextPtr)(
	__in  SIGNER_CONTEXT *pSignerContext
	);


HRESULT WINAPI SignerTimeStamp(
	_In_     SIGNER_SUBJECT_INFO *pSubjectInfo,
	_In_     LPCWSTR             pwszHttpTimeStamp,
	_In_opt_ PCRYPT_ATTRIBUTES   psRequest,
	_In_opt_ LPVOID              pSipData
	);

typedef HRESULT(WINAPI *SignerTimeStampPtr)(
	_In_     SIGNER_SUBJECT_INFO *pSubjectInfo,
	_In_     LPCWSTR             pwszHttpTimeStamp,
	_In_opt_ PCRYPT_ATTRIBUTES   psRequest,
	_In_opt_ LPVOID              pSipData
	);

class MsSign32
{
public:
	static SignerSignPtr SignerSign;
	static SignerSignExPtr SignerExSign;
	static SignerFreeSignerContextPtr SignerFreeSignerContext;
	static SignerTimeStampPtr SignerTimeStamp;

	static HRESULT Init();

private:
	static HMODULE _hMsSignDll;
};