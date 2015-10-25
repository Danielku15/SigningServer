// SigningServer.Server.PE.h

#pragma once

#using <SigningServer.Contracts.dll>

using namespace System;
using namespace System::Security::Cryptography::X509Certificates;
using namespace SigningServer::Contracts;

namespace SigningServer {
	namespace Server {
		namespace PE {
			public ref class PortableExectuableSigningTool 
				: public ISigningTool
			{
			public:
				PortableExectuableSigningTool();

				bool IsCompatibleWith(String^ fileName) override;
				void SignFile(String^ inputFileName, X509Certificate2^ certificate, SignFileRequest^ signFileRequest, SignFileResponse^ signFileResponse) override;
			};
		}
	}
}