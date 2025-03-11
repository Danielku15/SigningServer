using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using SigningServer.Client;
using SigningServer.ClientCore.Configuration;

namespace SigningServer.Test;

public class ConfigLoadTest
{
    [Test]
    public void TestPopulateObject()
    {
        var config = new SigningClientConfiguration { Username = "Test", Password = "Test" };

        JsonPopulate.PopulateObject(
            """
            { "Password": "Test2", "LoadCertificateChain": true }
            """,
            typeof(SigningClientConfiguration),
            config,
            DefaultSigningConfigurationLoader<SigningClientConfiguration>.JsonOptions);

        JsonPopulate.PopulateObject(
            """
            { "Username": "Test2" }
            """,
            typeof(SigningClientConfiguration),
            config,
            DefaultSigningConfigurationLoader<SigningClientConfiguration>.JsonOptions);

        config.Username.Should().Be("Test2");
        config.Password.Should().Be("Test2");
        config.LoadCertificateChain.Should().BeTrue();
    }

    [Test]
    public async Task FullLoadTestDefaultConfig()
    {
        var dir = Environment.CurrentDirectory;
        try
        {
            Environment.CurrentDirectory = Path.Combine(dir, "ConfigFiles");
            var builder = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?> { ["SigningServer"] = "http://localhost" });
            var loader = new DefaultSigningConfigurationLoader<SigningClientConfiguration>(
                builder.Build(),
                new NullLogger<DefaultSigningConfigurationLoader<SigningClientConfiguration>>(),
                [
                    "--timeout", "1234"
                ]);

            var config = await loader.LoadConfigurationAsync();
            config.Should().NotBeNull();
            config!.Username.Should().Be("default");
            config.Password.Should().Be("default");
            config.SigningServer.Should().Be("http://localhost");
            config.Timeout.Should().Be(1234);
        }
        finally
        {
            Environment.CurrentDirectory = dir;
        }
    }

    [Test]
    public async Task FullLoadTestCustomConfig()
    {
        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["SigningServer"] = "http://localhost" });
        var loader = new DefaultSigningConfigurationLoader<SigningClientConfiguration>(
            builder.Build(),
            new NullLogger<DefaultSigningConfigurationLoader<SigningClientConfiguration>>(),
            [
                "--config", "ConfigFiles/config_custom.json",
                "--timeout", "1234"
            ]);

        var config = await loader.LoadConfigurationAsync();
        config.Should().NotBeNull();
        config!.Username.Should().Be("custom");
        config.Password.Should().Be("custom");
        config.SigningServer.Should().Be("http://localhost");
        config.Timeout.Should().Be(1234);
    }
}
