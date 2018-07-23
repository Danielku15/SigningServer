#pragma once

#include <Windows.h>

using namespace System;
using namespace System::Collections::Generic;
using namespace System::Security::Cryptography::X509Certificates;
using namespace SigningServer::Contracts;
using namespace NLog;

namespace SigningServer {
    namespace Server {
        namespace Appx {

            public ref class AppxSigningTool
                : public ISigningTool
            {
            public:
                AppxSigningTool();
                static AppxSigningTool();
                virtual ~AppxSigningTool();

                virtual bool IsFileSupported(String^ fileName);
                property array<String^>^ SupportedFileExtensions { virtual array<String^>^ get(); }
                property array<String^>^ SupportedHashAlgorithms { virtual array<String^>^ get(); }

                virtual void SignFile(String^ inputFileName, X509Certificate2^ certificate, String^ timestampUrl, SignFileRequest^ signFileRequest, SignFileResponse^ signFileResponse);
                virtual bool IsFileSigned(String^ fileName);

            private:
                static initonly Logger^ Log;
                static initonly HashSet<String^>^ AppxSupportedExtensions;
                static initonly Dictionary<String^, unsigned int>^ AppxSupportedHashAlgorithms;
                static initonly bool CanSign;
            };

        }
    }
}
