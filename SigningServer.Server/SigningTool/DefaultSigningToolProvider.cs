using Microsoft.Extensions.Logging;
using SigningServer.Android;
using SigningServer.ClickOnce;
using SigningServer.Contracts;
using SigningServer.MsSign;

namespace SigningServer.Server.SigningTool;

public class DefaultSigningToolProvider : EnumerableSigningToolProvider
{
    public DefaultSigningToolProvider(ILoggerFactory loggerFactory)
        : base(new ISigningTool[]
        {
            new PortableExecutableSigningTool(loggerFactory.CreateLogger<PortableExecutableSigningTool>()),
            new AndroidApkSigningTool(), new JarSigningTool(),
            new AppxSigningTool(loggerFactory.CreateLogger<AppxSigningTool>()),
            new ClickOnceSigningTool(loggerFactory.CreateLogger<ClickOnceSigningTool>()),
            new PowerShellSigningTool(loggerFactory.CreateLogger<PowerShellSigningTool>())
        })
    {
    }
}