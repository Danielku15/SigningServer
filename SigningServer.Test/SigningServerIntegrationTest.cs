﻿using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Newtonsoft.Json;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Client;
using SigningServer.Server;
using SigningServer.Server.Configuration;

namespace SigningServer.Test
{
    [TestClass]
    public class SigningServerIntegrationTest : UnitTestBase
    {
        private static SigningServerService _service;

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
                        Certificate = new SigningCertificateFromPfxFile(CertificatePath, CertificatePassword)
                    }
                },
                WorkingDirectory = "WorkingDirectory"
            };

            _service = new SigningServerService(configuration);
            _service.ConsoleStart();
        }

        [ClassCleanup]
        public static void TearDown()
        {
            _service.ConsoleStop();
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "IntegrationTestFiles")]
        public void ValidTestRun()
        {
            var client = new SigningClient(new SigningClientConfiguration
            {
                SigningServer = "localhost:4711"
            });
            client.SignFile(Path.Combine(ExecutionDirectory, "IntegrationTestFiles/unsigned"));

            Assert.AreEqual(0, Directory.GetFiles("WorkingDirectory").Length, "Server Side file cleanup failed");

            var signedFiles = Directory.GetFiles(Path.Combine(ExecutionDirectory, "IntegrationTestFiles"));
            var signingTools = _service.SigningServer.SigningToolProvider;

            foreach (var signedFile in signedFiles)
            {
                var tool = signingTools.GetSigningTool(signedFile);
                Assert.IsNotNull(tool, "Could not find signing tool for file {0}", signedFile);

                Assert.IsTrue(tool.IsFileSigned(signedFile), "File {0} was not signed", signedFile);
            }

        }

    }
}
