using SigningServer.Android;
using SigningServer.ClickOnce;
using SigningServer.Contracts;
using SigningServer.MsSign;
using SigningServer.Server.SigningTool;

namespace SigningServer.Server
{
    public class DefaultSigningToolProvider : EnumerableSigningToolProvider
    {
        private static readonly ISigningTool[] SigningTools =
        {
            new PortableExecutableSigningTool(),
            new AndroidApkSigningTool(),
            new JarSigningTool(),
            new AppxSigningTool(),
            new ClickOnceSigningTool(),
            new PowerShellSigningTool()
        };

        public DefaultSigningToolProvider()
            : base(SigningTools)
        {
        }
    }
}