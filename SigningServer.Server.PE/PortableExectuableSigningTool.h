#pragma once

#include <Windows.h>

using namespace System;
using namespace System::Collections::Generic;
using namespace System::Security::Cryptography::X509Certificates;
using namespace SigningServer::Contracts;
using namespace NLog;

namespace SigningServer { namespace Server { namespace PE {

	public ref class PortableExectuableSigningTool
		: public ISigningTool
	{
	public:
		PortableExectuableSigningTool();
		static PortableExectuableSigningTool();
		virtual ~PortableExectuableSigningTool();

		virtual bool IsFileSupported(String^ fileName);
		virtual array<String^>^ GetSupportedFileExtensions();
		
		virtual void SignFile(String^ inputFileName, X509Certificate2^ certificate, String^ timestampUrl, SignFileRequest^ signFileRequest, SignFileResponse^ signFileResponse);
		virtual bool IsFileSigned(String^ fileName);
		virtual void UnsignFile(String^ fileName);

	private:
		static initonly Logger^ Log;
		static initonly HashSet<String^>^ SupportedExtensions;
		static initonly bool CanSign;
	};

}
}
}
