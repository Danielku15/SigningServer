using System;
using System.Net;
using CoreWCF;
using CoreWCF.Configuration;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using SigningServer.Contracts;
using SigningServer.Server.Configuration;
using SigningServer.Server.SigningTool;

namespace SigningServer.Server;

public class Startup
{
    private readonly SigningServerConfiguration _signingServerConfiguration;

    public Startup(SigningServerConfiguration signingServerConfiguration)
    {
        _signingServerConfiguration = signingServerConfiguration;
    }

    public void ConfigureServices(IServiceCollection services)
    {
        services.AddServiceModelServices();
        services.AddSingleton<ISigningToolProvider, DefaultSigningToolProvider>();
        services.AddSingleton<SigningServer>();
    }

    public void Configure(IApplicationBuilder app)
    {
        app.UseServiceModel(builder =>
        {
            builder.AddService<SigningServer>();
            var uri = new UriBuilder
            {
                Scheme = "net.tcp", Host = Dns.GetHostName(), Port = _signingServerConfiguration.Port
            };
            var binding = new NetTcpBinding
            {
                TransferMode = TransferMode.Streamed,
                MaxReceivedMessageSize = int.MaxValue,
                MaxBufferSize = int.MaxValue,
                OpenTimeout = TimeSpan.FromMinutes(5),
                CloseTimeout = TimeSpan.FromMinutes(5),
                SendTimeout = TimeSpan.FromMinutes(60),
                ReceiveTimeout = TimeSpan.FromMinutes(60),
                MaxConnections = int.MaxValue,
                Security =
                {
                    Mode = SecurityMode.None
                }
            };
            builder.AddServiceEndpoint<SigningServer, ISigningServer>(binding, uri.Uri);
        });
    }
}
