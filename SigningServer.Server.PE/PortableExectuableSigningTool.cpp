#include "stdafx.h"

#include <vcclr.h>

#include "PortableExectuableSigningTool.h"
#include "mssign32.h"

#include <Softpub.h>
#include <WinTrust.h>
#include <Imagehlp.h>
using namespace System::Security::Cryptography;

SigningServer::Server::PE::PortableExectuableSigningTool::PortableExectuableSigningTool(ILogger^ log)
	: m_log(log)
{
	if (!CanSign)
	{
		log->Error(String::Format("Could not load mssign32.dll."));
	}
}

static SigningServer::Server::PE::PortableExectuableSigningTool::PortableExectuableSigningTool()
{
	PESupportedExtensions = gcnew HashSet<String^>(gcnew array<String^> {
		".exe", ".dll", ".sys", ".msi", ".cab"
		// , ".drv", ".scr", ".cpl", ".ocx", ".ax", ".efi"
	}, System::StringComparer::CurrentCultureIgnoreCase);

	PESupportedHashAlgorithms = gcnew Dictionary<String^, unsigned int>(System::StringComparer::CurrentCultureIgnoreCase);
	PESupportedHashAlgorithms["SHA1"] = CALG_SHA1;
	PESupportedHashAlgorithms["MD5"] = CALG_MD5;
	PESupportedHashAlgorithms["SHA256"] = CALG_SHA_256;
	PESupportedHashAlgorithms["SHA384"] = CALG_SHA_384;
	PESupportedHashAlgorithms["SHA512"] = CALG_SHA_512;

	HRESULT mssign = MsSign32::Init();
	CanSign = mssign == ERROR_SUCCESS;
}


SigningServer::Server::PE::PortableExectuableSigningTool::~PortableExectuableSigningTool()
{
}

array<String^>^ SigningServer::Server::PE::PortableExectuableSigningTool::SupportedFileExtensions::get()
{
	return System::Linq::Enumerable::ToArray(PESupportedExtensions);
}

array<String^>^ SigningServer::Server::PE::PortableExectuableSigningTool::SupportedHashAlgorithms::get()
{
	return System::Linq::Enumerable::ToArray(PESupportedHashAlgorithms->Keys);
}

bool SigningServer::Server::PE::PortableExectuableSigningTool::IsFileSupported(String^ fileName)
{
	return CanSign && PESupportedExtensions->Contains(System::IO::Path::GetExtension(fileName));
}

bool SigningServer::Server::PE::PortableExectuableSigningTool::IsFileSigned(String^ inputFileName)
{
	pin_ptr<const wchar_t> pwszSourceFile = PtrToStringChars(inputFileName);

	WINTRUST_FILE_INFO winTrustFileInfo;
	memset(&winTrustFileInfo, 0, sizeof(winTrustFileInfo));
	winTrustFileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
	winTrustFileInfo.pcwszFilePath = pwszSourceFile;
	winTrustFileInfo.hFile = nullptr;
	winTrustFileInfo.pgKnownSubject = nullptr;

	WINTRUST_DATA winTrustData;
	memset(&winTrustData, 0, sizeof(winTrustData));
	winTrustData.cbStruct = sizeof(winTrustData);
	winTrustData.pPolicyCallbackData = nullptr;
	winTrustData.pSIPClientData = nullptr;
	winTrustData.dwUIChoice = WTD_UI_NONE;
	winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
	winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
	winTrustData.hWVTStateData = nullptr;
	winTrustData.pwszURLReference = nullptr;
	winTrustData.dwUIContext = 0;
	winTrustData.pFile = &winTrustFileInfo;

	GUID actionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	DWORD result = WinVerifyTrust(
		nullptr,
		&actionId,
		&winTrustData
		);
	m_log->Trace(String::Format("WinVerifyTrust returned {0}", result));
	DWORD dwLastError;

	switch (result)
	{
	case ERROR_SUCCESS:
		return true;
	case TRUST_E_NOSIGNATURE:
		dwLastError = GetLastError();
		switch (dwLastError)
		{
		case TRUST_E_NOSIGNATURE:
			return false;
		case TRUST_E_SUBJECT_FORM_UNKNOWN:
			return true;
		case TRUST_E_PROVIDER_UNKNOWN:
			return true;
		default:
			return false;
		}

		break;

	case CERT_E_UNTRUSTEDROOT:
		return true;

	case TRUST_E_EXPLICIT_DISTRUST:
		return true;

	case TRUST_E_SUBJECT_NOT_TRUSTED:
		return true;

	case CRYPT_E_SECURITY_SETTINGS:
		return true;

	default:
		return false;
	}

	return false;
}

void SigningServer::Server::PE::PortableExectuableSigningTool::UnsignFile(String^ fileName)
{
	pin_ptr<const wchar_t> pwszFileName = PtrToStringChars(fileName);
	HANDLE hFile = CreateFile(pwszFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
	if (!hFile)
	{
		throw gcnew System::IO::FileNotFoundException("the file that was requested to unsigned could not be found", fileName);
	}

	// TODO: remove multiple certificates here?
	DWORD dwNumCerts;
	if (ImageEnumerateCertificates(hFile, CERT_SECTION_TYPE_ANY, &dwNumCerts, NULL, 0) && dwNumCerts == 1)
	{
		ImageRemoveCertificate(hFile, 0);
	}
	CloseHandle(hFile);
}


void SigningServer::Server::PE::PortableExectuableSigningTool::SignFile(String^ inputFileName, X509Certificate2^ certificate, String^ timeStampUrl, SignFileRequest^ signFileRequest, SignFileResponse^ signFileResponse)
{
	if (!CanSign)
	{
		throw gcnew InvalidOperationException("mssign32.dll could not be loaded");
	}

	SignFileResponseResult successResult = SignFileResponseResult::FileSigned;

	if (IsFileSigned(inputFileName))
	{
		if (signFileRequest->OverwriteSignature)
		{
			m_log->Trace(String::Format("File {0} is already signed, removing signature", inputFileName));
			UnsignFile(inputFileName);
			successResult = SignFileResponseResult::FileResigned;
		}
		else
		{
			m_log->Trace(String::Format("File {0} is already signed, abort signing", inputFileName));
			signFileResponse->Result = SignFileResponseResult::FileAlreadySigned;
			return;
		}
	}

	array<Byte>^ rawCertData = certificate->GetRawCertData();
	pin_ptr<BYTE> rawCertDataPin = &rawCertData[0];
	BYTE * nativeRawCertCata = rawCertDataPin;

	m_log->Trace(String::Format("Creating certificate context", inputFileName));
	PCCERT_CONTEXT pCertContext = CertCreateCertificateContext(
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		nativeRawCertCata,
		rawCertData->Length
		);
	if (!pCertContext)
	{
		signFileResponse->Result = SignFileResponseResult::FileNotSignedError;
		signFileResponse->ErrorMessage = String::Format("could not create certificate context from certificate (0x{0:X})", GetLastError());
		return;
	}

	pin_ptr<const wchar_t> pwszFileName = PtrToStringChars(inputFileName);

	SIGNER_FILE_INFO signerFileInfo;
	signerFileInfo.cbSize = sizeof(SIGNER_FILE_INFO);
	signerFileInfo.pwszFileName = pwszFileName;
	signerFileInfo.hFile = nullptr;

	SIGNER_SUBJECT_INFO signerSubjectInfo;
	signerSubjectInfo.cbSize = sizeof(SIGNER_SUBJECT_INFO);
	DWORD dwIndex = 0;
	signerSubjectInfo.pdwIndex = &dwIndex;
	signerSubjectInfo.dwSubjectChoice = SIGNER_SUBJECT_FILE;
	signerSubjectInfo.pSignerFileInfo = &signerFileInfo;

	SIGNER_CERT_STORE_INFO signerCertStoreInfo;
	signerCertStoreInfo.cbSize = sizeof(signerCertStoreInfo);
	signerCertStoreInfo.pSigningCert = pCertContext;
	signerCertStoreInfo.dwCertPolicy = SIGNER_CERT_POLICY_CHAIN;
	signerCertStoreInfo.hCertStore = nullptr;

	SIGNER_CERT signerCert;
	signerCert.cbSize = sizeof(SIGNER_CERT);
	signerCert.dwCertChoice = SIGNER_CERT_STORE;
	signerCert.pCertStoreInfo = &signerCertStoreInfo;
	signerCert.hwnd = nullptr;

	ALG_ID algidHash;
	if (!PESupportedHashAlgorithms->TryGetValue(signFileRequest->HashAlgorithm == nullptr ? "" : signFileRequest->HashAlgorithm, algidHash))
	{
		algidHash = CALG_SHA_256;
	}

	SIGNER_SIGNATURE_INFO signerSignatureInfo;
	signerSignatureInfo.cbSize = sizeof(signerSignatureInfo);
	signerSignatureInfo.algidHash = algidHash;
	signerSignatureInfo.dwAttrChoice = SIGNER_NO_ATTR;
	signerSignatureInfo.pAttrAuthcode = nullptr;
	signerSignatureInfo.psAuthenticated = nullptr;
	signerSignatureInfo.psUnauthenticated = nullptr;


	ICspAsymmetricAlgorithm^ algorithm = (ICspAsymmetricAlgorithm^)certificate->PrivateKey;
	pin_ptr<const wchar_t> pwszProviderName = PtrToStringChars(algorithm->CspKeyContainerInfo->ProviderName);
	pin_ptr<const wchar_t> pwszKeyContainer = PtrToStringChars(algorithm->CspKeyContainerInfo->KeyContainerName);

	SIGNER_PROVIDER_INFO signerProviderInfo;
	signerProviderInfo.cbSize = sizeof(SIGNER_PROVIDER_INFO);
	signerProviderInfo.pwszProviderName = pwszProviderName;
	signerProviderInfo.dwProviderType = algorithm->CspKeyContainerInfo->ProviderType;
	signerProviderInfo.dwPvkChoice = PVK_TYPE_KEYCONTAINER;
	signerProviderInfo.pwszKeyContainer = (LPWSTR)pwszKeyContainer;

	m_log->Trace(String::Format("Call signing of  {0}", inputFileName));
	SIGNER_CONTEXT* pSignerContext = nullptr;
	HRESULT hr = MsSign32::SignerSign(&signerSubjectInfo, &signerCert, &signerSignatureInfo, &signerProviderInfo, nullptr, nullptr, &pSignerContext);

	HRESULT tshr = S_OK;
	if (!String::IsNullOrWhiteSpace(timeStampUrl))
	{
		m_log->Trace(String::Format("Timestamping with url {0}", timeStampUrl));
		pin_ptr<const wchar_t> pwszTimestampUrl = PtrToStringChars(timeStampUrl);
		int timestampRetries = 5;
		do
		{
			tshr = MsSign32::SignerTimeStamp(&signerSubjectInfo, pwszTimestampUrl, nullptr, nullptr);
			if (tshr == S_OK)
			{
				m_log->Trace(String::Format("Timestamping succeeded"));
			}
			else
			{
				m_log->Trace(String::Format("Timestamping failed with {0}, retries: {1}", tshr, timestampRetries));
				System::Threading::Thread::Sleep(1000);
			}
		} while (tshr != S_OK && (timestampRetries--) > 0);
	}

	if (pSignerContext)
	{
		MsSign32::SignerFreeSignerContext(pSignerContext);
	}

	if (pCertContext)
	{
		CertFreeCertificateContext(pCertContext);
	}

	if (hr == S_OK && tshr == S_OK)
	{
		m_log->Trace(String::Format("{0} successfully signed", inputFileName));
		signFileResponse->Result = successResult;
		signFileResponse->FileContent = gcnew System::IO::FileStream(inputFileName, System::IO::FileMode::Open, System::IO::FileAccess::Read);
		signFileResponse->FileSize = signFileResponse->FileContent->Length;
	}
	else if(hr != S_OK)
	{
		LPTSTR errorText = nullptr;
		FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
			nullptr,
			hr,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR)&errorText,
			0,
			nullptr
			);

		signFileResponse->Result = SignFileResponseResult::FileNotSignedError;
		if (errorText != nullptr)
		{
			signFileResponse->ErrorMessage = gcnew String(errorText);
			LocalFree(errorText);
			errorText = nullptr;
		}
		else
		{
			signFileResponse->ErrorMessage = String::Format("signing file failed (0x{0:x})", hr);
		}
		m_log->Error(String::Format("{0} signing failed {1}", inputFileName, signFileResponse->ErrorMessage));
	}
	else
	{
		LPTSTR errorText = nullptr;
		FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
			nullptr,
			tshr,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR)&errorText,
			0,
			nullptr
			);

		signFileResponse->Result = SignFileResponseResult::FileNotSignedError;
		if (errorText != nullptr)
		{
			signFileResponse->ErrorMessage = gcnew String(errorText);
			LocalFree(errorText);
			errorText = nullptr;
		}
		else
		{
			signFileResponse->ErrorMessage = String::Format("timestamping failed (0x{0:x})", hr);
		}
		m_log->Error(String::Format("{0} timestamping failed {1}", inputFileName, signFileResponse->ErrorMessage));
	}
}