using SigningServer.Contracts;
using SigningServer.Server.SigningTool;

namespace SigningServer.Server
{
    public class DefaultSigningToolProvider : EnumerableSigningToolProvider
    {
        private static readonly ISigningTool[] SigningTools =
        {
            new PortableExecutableSigningTool(),
            new AndroidApkSigningTool(),
            new ClickOnceSigningTool(),
            new AppxSigningTool(),
            new PowerShellSigningTool()
        };

        public DefaultSigningToolProvider()
            : base(SigningTools)
        {
        }
    }
}