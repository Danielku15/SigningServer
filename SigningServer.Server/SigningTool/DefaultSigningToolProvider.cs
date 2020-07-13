using NLog;
using SigningServer.Contracts;
using SigningServer.Server.PE;
using SigningServer.Server.SigningTool;

namespace SigningServer.Server
{
    public class DefaultSigningToolProvider : EnumerableSigningToolProvider
    {
	    private static readonly Logger Log = LogManager.GetCurrentClassLogger();
        private static readonly ISigningTool[] SigningTools =
        {
            new PortableExectuableSigningTool(LogFunction),
            new AndroidApkSigningTool()
        };

        public DefaultSigningToolProvider()
            : base(SigningTools)
        {
            
        }

        private static void LogFunction(string message)
        {
            Log.Info(message);
        }
    }
}