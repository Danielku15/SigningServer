using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CoreWCF.Configuration;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Client;
using SigningServer.Contracts;
using SigningServer.Server;
using SigningServer.Server.Configuration;

namespace SigningServer.Test
{
    [TestClass]
    public class SigningServerIntegrationTest : UnitTestBase
    {
        private static IWebHost _service;

        [ClassInitialize]
        public static void Setup(TestContext _)
        {
            var configuration = new SigningServerConfiguration
            {
                Port = 4711,
                TimestampServer = TimestampServer,
                Sha1TimestampServer = Sha1TimestampServer,
                Certificates = new[]
                {
                    new CertificateConfiguration
                    {
                        Certificate = AssemblyEvents.Certificate,
                        PrivateKey = AssemblyEvents.PrivateKey
                    }
                },
                WorkingDirectory = "WorkingDirectory"
            };
            var builder = WebHost.CreateDefaultBuilder()
                .ConfigureServices(services =>
                {
                    services.AddSingleton(configuration);
                })
                .UseKestrel()
                .UseNetTcp(configuration.Port)
                .UseStartup<Startup>();
            _service = builder.Build();
            _service.Start();
        }

        [ClassCleanup]
        public static async Task TearDown()
        {
            await _service.StopAsync();
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "IntegrationTestFiles")]
        public void ValidTestRun()
        {
            using (var client = new SigningClient(new SigningClientConfiguration
                   {
                       SigningServer = "localhost:4711"
                   }))
            {
                client.SignFile(Path.Combine(ExecutionDirectory, "IntegrationTestFiles/unsigned"));
            }

            Assert.AreEqual(0, Directory.GetFiles("WorkingDirectory").Length, "Server Side file cleanup failed");

            var signedFiles = Directory.GetFiles(Path.Combine(ExecutionDirectory, "IntegrationTestFiles"));
            var signingTools = _service.Services.GetRequiredService<ISigningToolProvider>();

            foreach (var signedFile in signedFiles)
            {
                var tool = signingTools.GetSigningTool(signedFile);
                Assert.IsNotNull(tool, "Could not find signing tool for file {0}", signedFile);

                Assert.IsTrue(tool.IsFileSigned(signedFile), "File {0} was not signed", signedFile);
            }
        }

        [TestMethod]
        public void ConcurrentSigning()
        {
            var testDir = Path.Combine(ExecutionDirectory, "IntegrationTestFiles/large");
            Directory.CreateDirectory(testDir);

            var referenceTestFile = GenerateLargeTestFile(Path.Combine(testDir, "TestFile.reference"));
            var testFiles = new string [4];
            for (var i = 0; i < testFiles.Length; i++)
            {
                var file = Path.Combine(testDir, "TestFile" + i + ".ps1");
                File.Copy(referenceTestFile, file, true);
                testFiles[i] = file;
            }

            var tasks = testFiles.Select((f, i) => Task.Run(async () =>
            {
                await Task.Delay(i * 50); // slight delay to trigger not exactly the same time 
                var sw = Stopwatch.StartNew();
                using (var client = new SigningClient(new SigningClientConfiguration
                       {
                           SigningServer = "localhost:4711"
                       }))
                {
                    client.SignFile(f);
                }
                return sw.Elapsed;
            })).ToArray();

            Task.WaitAll(tasks.ToArray<Task>());

            // check for successful signing
            var signedFiles = Directory.GetFiles(testDir, "*.ps1");
            var signingTools = _service.Services.GetRequiredService<ISigningToolProvider>();
            foreach (var signedFile in signedFiles)
            {
                var tool = signingTools.GetSigningTool(signedFile);
                Assert.IsNotNull(tool, "Could not find signing tool for file {0}", signedFile);

                Assert.IsTrue(tool.IsFileSigned(signedFile), "File {0} was not signed", signedFile);
            }

            var times = tasks.Select(t => t.Result).ToArray();
            var average = times.Average(t => t.TotalMilliseconds);
            var threshold = times.Min(t => t.TotalMilliseconds) * 2;
            for (var i = 0; i < times.Length; i++)
            {
                if (times[i].TotalMilliseconds > threshold)
                {
                    Assert.Fail(
                        $"Performance test failed, needed {times[i].TotalMilliseconds}ms for file {testFiles[i]} with average of {average} and threshold of {threshold}");
                }
            }
        }

        private string GenerateLargeTestFile(string path)
        {
            using var writer = new FileStream(path, FileMode.Create, FileAccess.Write);
            var size = 100 * 1024 * 1024;
            var simpleLine = Encoding.UTF8.GetBytes("Write-Host Hello World" + Environment.NewLine);
            while (size > 0)
            {
                writer.Write(simpleLine, 0, simpleLine.Length);
                size -= simpleLine.Length;
            }

            return path;
        }
    }
}
