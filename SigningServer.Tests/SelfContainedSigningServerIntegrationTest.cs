using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Reflection;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using SigningServer.Client;
using SigningServer.ClientCore;
using SigningServer.ClientCore.Configuration;

namespace SigningServer.Test;

[NonParallelizable]
public class SelfContainedSigningServerIntegrationTest : SigningServerIntegrationTestBase
{
    protected override int ConcurrentSigningAverageThresholdFactor => 3;

    protected override IIntegrationTestServer CreateApplicationInstance(Action<IWebHostBuilder> webHostBuilder)
    {
        return new HttpIntegrationTestServer(webHostBuilder);
    }

    protected override ISigningClient CreateSigningClient(params string[] sources)
    {
        var configuration =
#if DEBUG
            "Debug";
#else
            "Release";
#endif
        var executable = Path.Combine(RepositoryRoot, "SigningServer.Client", "bin", configuration, "net9.0", "win-x64",
            "publish", "SigningServer.Client.exe");

        return new ExecutableSigningClient(executable,
            Application!.Services.GetRequiredService<ILogger<ExecutableSigningClient>>(),
            new SigningClientConfiguration
            {
                SigningServer = ((HttpIntegrationTestServer)Application!).BaseUrl.ToString(), Sources = sources
            });
    }

    public static readonly string RepositoryRoot = FindRepositoryRoot(new DirectoryInfo(Environment.CurrentDirectory));

    private static string FindRepositoryRoot(DirectoryInfo dir)
    {
        if (File.Exists(Path.Combine(dir.FullName, "SigningServer.sln")))
        {
            return dir.FullName;
        }

        if (dir.Parent == null)
        {
            throw new IOException("Could not find repository root");
        }

        return FindRepositoryRoot(dir.Parent);
    }

    private sealed class ExecutableSigningClient : ISigningClient
    {
        private readonly string _executable;
        private readonly ILogger<ExecutableSigningClient> _logger;
        private Process? _process;
        private string? _configFile;

        public ExecutableSigningClient(string executable, ILogger<ExecutableSigningClient> logger,
            SigningClientConfiguration configuration)
        {
            Configuration = configuration;
            _executable = executable;
            _logger = logger;
        }

        public void Dispose()
        {
            _process?.Dispose();
        }

        public async Task InitializeAsync()
        {
            _configFile = Path.Combine(Path.GetTempPath(), "config_" + Guid.NewGuid().ToString("N") + ".json");
            await using (var file = File.OpenWrite(_configFile))
            {
                await JsonSerializer.SerializeAsync(file,
                    (SigningClientConfiguration)Configuration,
                    SigningConfigurationHelper.JsonOptions
                );
            }

            _process = new Process
            {
                StartInfo = new ProcessStartInfo(_executable, [
                    "--config", _configFile,
                    ..Configuration.Sources
                ]) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false }
            };

            _process.OutputDataReceived += (sender, a) =>
            {
                if (a.Data != null)
                {
                    _logger.LogInformation("[SigningServer-{ProcessId}] {Data}", _process.Id, a.Data);
                }
            };
            _process.ErrorDataReceived += (sender, a) =>
            {
                if (a.Data != null)
                {
                    _logger.LogError("[SigningServer-{ProcessId}] {Data}", _process.Id, a.Data);
                }
            };
        }

        public async Task SignFilesAsync()
        {
            if (!_process!.Start())
            {
                throw new IOException("Process could not be started");
            }
            
            _process.BeginOutputReadLine();
            _process.BeginErrorReadLine();

            await _process.WaitForExitAsync();

            if (_process.ExitCode != 0)
            {
                throw new IOException("Signing completed with Exit Code " + _process.ExitCode);
            }
        }

        public SigningClientConfigurationBase Configuration { get; }
    }


    private sealed class HttpIntegrationTestServer(Action<IWebHostBuilder> configureWebHostBuilder)
        : IIntegrationTestServer
    {
        private IHost? _host;

        public void Start()
        {
            EnsureServer();
        }

        public IServiceProvider Services
        {
            get
            {
                EnsureServer();
                return _host!.Services;
            }
        }

        public Uri BaseUrl => new Uri($"http://localhost:5000");

        public HttpClient CreateClient()
        {
            return new HttpClient { BaseAddress = BaseUrl, Timeout = TimeSpan.FromSeconds(200), };
        }

        private void EnsureServer()
        {
            if (_host != null)
            {
                return;
            }

            lock (this)
            {
                if (_host != null)
                {
                    return;
                }

                // Adopted from TestServer
                var mvcTestAssembly = typeof(WebApplicationFactory<>).Assembly;
                var deferredHostBuilderType =
                    mvcTestAssembly.GetType(
                        "Microsoft.AspNetCore.Mvc.Testing.DeferredHostBuilder")!;
                var deferredHostBuilder = (IHostBuilder)Activator.CreateInstance(deferredHostBuilderType)!;

                deferredHostBuilder.UseEnvironment(Environments.Development);
                deferredHostBuilder.ConfigureHostConfiguration(config =>
                {
                    config.AddInMemoryCollection(new Dictionary<string, string?>
                    {
                        {
                            HostDefaults.ApplicationKey, typeof(Server.Program).Assembly.GetName().Name ?? string.Empty
                        }
                    });
                });

                var factory = mvcTestAssembly.GetType("Microsoft.Extensions.Hosting.HostFactoryResolver")!
                    .GetMethod("ResolveHostFactory", BindingFlags.Static | BindingFlags.Public)!
                    .Invoke(null, [
                        typeof(Server.Program).Assembly,
                        null,
                        false,
                        (Action<object>)(hostBuilder =>
                        {
                            deferredHostBuilder.GetType().GetMethod("ConfigureHostBuilder",
                                    BindingFlags.Instance | BindingFlags.Public)!
                                .Invoke(deferredHostBuilder, [hostBuilder]);
                        }),
                        (Action<Exception?>)(exception =>
                        {
                            deferredHostBuilder.GetType().GetMethod("EntryPointCompleted",
                                    BindingFlags.Instance | BindingFlags.Public)!
                                .Invoke(deferredHostBuilder, [exception]);
                        })
                    ]);

                if (factory is not null)
                {
                    deferredHostBuilder.GetType()
                        .GetMethod("SetHostFactory", BindingFlags.Instance | BindingFlags.Public)!
                        .Invoke(deferredHostBuilder, [factory]);
                    ConfigureHostBuilder(deferredHostBuilder);
                    return;
                }

                throw new InvalidOperationException("Could not create host builder");
            }
        }

        private void ConfigureHostBuilder(IHostBuilder hostBuilder)
        {
            hostBuilder.ConfigureWebHost(webHostBuilder =>
            {
                webHostBuilder.UseSolutionRelativeContentRoot("SigningServer.Server");
                configureWebHostBuilder(webHostBuilder);
                webHostBuilder.UseKestrel();
            });
            _host = CreateHost(hostBuilder);
        }

        private static IHost CreateHost(IHostBuilder builder)
        {
            var host = builder.Build();
            host.Start();
            return host;
        }

        void IDisposable.Dispose()
        {
            _host?.Dispose();
        }
    }
}
