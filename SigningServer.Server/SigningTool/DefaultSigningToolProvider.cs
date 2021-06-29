using NLog;
using SigningServer.Contracts;
using SigningServer.Server.Appx;
using SigningServer.Server.PE;
using SigningServer.Server.SigningTool;

namespace SigningServer.Server
{
    public class DefaultSigningToolProvider : EnumerableSigningToolProvider
    {
	    private static readonly ILogger Log = new NLogLogger(LogManager.GetCurrentClassLogger());
        private static readonly ISigningTool[] SigningTools =
        {
            new PortableExectuableSigningTool(Log),
            new AndroidApkSigningTool(),
            new ClickOnceSigningTool(),
            new AppxSigningTool(Log),
            new PowerShellSigningTool()
        };

        public DefaultSigningToolProvider()
            : base(SigningTools)
        {
        }
    }
}