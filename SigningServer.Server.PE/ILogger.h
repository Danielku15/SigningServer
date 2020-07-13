#pragma once

namespace SigningServer {
    namespace Server {
        public interface class ILogger {
            void Error(System::String^ message);
            void Warn(System::String^ message);
            void Info(System::String^ message);
            void Debug(System::String^ message);
            void Trace(System::String^ message);
        };
    }
}