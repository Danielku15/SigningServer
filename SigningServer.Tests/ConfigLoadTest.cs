using System;
using System.IO;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using SigningServer.Client;
using SigningServer.ClientCore;
using SigningServer.ClientCore.Configuration;

namespace SigningServer.Test;

public class ConfigLoadTest
{
    [Test]
    public async Task FullLoadTestDefaultConfig()
    {
        var dir = Environment.CurrentDirectory;
        try
        {
            string[] args =
            [
                "--timeout", "1234"
            ];

            Environment.CurrentDirectory = Path.Combine(dir, "ConfigFiles");

            var host = Host.CreateDefaultBuilder()
                .UseSigningClientConfiguration(args)
                .Build();

            var loader = new DefaultSigningConfigurationLoader<SigningClientConfiguration>(
                host.Services.GetRequiredService<IConfiguration>(),
                host.Services
                    .GetRequiredService<ILogger<DefaultSigningConfigurationLoader<SigningClientConfiguration>>>(),
                args);

            var config = await loader.LoadConfigurationAsync();
            config.Should().NotBeNull();
            config!.Username.Should().Be("default");
            config.Password.Should().Be("default");
            config.SigningServer.Should().BeEmpty();
            config.Timeout.Should().Be(1234);
        }
        finally
        {
            Environment.CurrentDirectory = dir;
        }
    }

    [Test]
    public void MissingConfigFileArg()
    {
        string[] args =
        [
            "--config"
        ];

        using var host = Host.CreateDefaultBuilder()
            .UseSigningClientConfiguration(args)
            .Build();

        var exitCode = Environment.ExitCode;
        Environment.ExitCode = 0;
        exitCode.Should().Be(ErrorCodes.InvalidConfiguration);
    }
    
    [Test]
    public void MissingConfigFile()
    {
        string[] args =
        [
            "--config", "NotExisting.json"
        ];

        using var host = Host.CreateDefaultBuilder()
            .UseSigningClientConfiguration(args)
            .Build();

        var exitCode = Environment.ExitCode;
        Environment.ExitCode = 0;
        exitCode.Should().Be(ErrorCodes.InvalidConfiguration);
    }

    [Test]
    public async Task FullLoadTestCustomConfig()
    {
        string[] args =
        [
            "--config", "ConfigFiles/config_custom.json",
            "--timeout", "1234"
        ];

        var host = Host.CreateDefaultBuilder()
            .UseSigningClientConfiguration(args)
            .Build();

        var loader = new DefaultSigningConfigurationLoader<SigningClientConfiguration>(
            host.Services.GetRequiredService<IConfiguration>(),
            host.Services.GetRequiredService<ILogger<DefaultSigningConfigurationLoader<SigningClientConfiguration>>>(),
            args);

        var config = await loader.LoadConfigurationAsync();
        config.Should().NotBeNull();
        config!.Username.Should().Be("custom");
        config.Password.Should().Be("custom");
        config.SigningServer.Should().BeEmpty();
        config.Timeout.Should().Be(1234);
    }
}
