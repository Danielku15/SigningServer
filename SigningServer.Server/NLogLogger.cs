using NLog;

namespace SigningServer.Server
{
    public class NLogLogger : ILogger
    {
        private readonly NLog.ILogger _log;

        public NLogLogger(NLog.ILogger log)
        {
            _log = log;
        }

        public NLogLogger(string loggerName)
        {
            _log = LogManager.GetLogger(loggerName);
        }

        public void Debug(string message)
        {
            _log.Debug(message);
        }

        public void Error(string message)
        {
            _log.Error(message);
        }

        public void Info(string message)
        {
            _log.Info(message);
        }

        public void Trace(string message)
        {
            _log.Trace(message);
        }

        public void Warn(string message)
        {
            _log.Warn(message);
        }
    }
}
