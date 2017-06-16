using System;
using System.IO;
using System.Net;
using System.Reflection;
using System.ServiceModel;
using System.ServiceProcess;
using Newtonsoft.Json;
using NLog;
using SigningServer.Contracts;
using SigningServer.Server.Configuration;

namespace SigningServer.Server
{
    public partial class SigningServerService : ServiceBase
    {
        private static readonly Logger Log = LogManager.GetCurrentClassLogger();

        private ServiceHost _serviceHost;

        public SigningServerService()
        {
            InitializeComponent();
        }

        public SigningServer SigningServer
        {
            get; private set;
        }

        public void ConsoleStart()
        {
            OnStart(new string[0]);
        }

        protected override void OnStart(string[] args)
        {
            Log.Info("Starting Signing Server");

            string configFileLocation;
            var executable = Assembly.GetEntryAssembly();
            if (executable != null)
            {
                configFileLocation = new FileInfo(executable.Location).DirectoryName;
            }
            else
            {
                configFileLocation = Environment.CurrentDirectory;
            }


            var configFile = Path.Combine(configFileLocation, "config.json");
            if (!File.Exists(configFile))
            {
                Log.Fatal("Could not find config.json beside executable");
                Stop();
                return;
            }

            try
            {
                Log.Info("Loading configuration");
                var configuration = JsonConvert.DeserializeObject<SigningServerConfiguration>(File.ReadAllText(configFile));
                Log.Info("Starting server");

                SigningServer = new SigningServer(configuration, new DefaultSigningToolProvider());
                _serviceHost = new ServiceHost(SigningServer);
                var uri = new UriBuilder
                {
                    Scheme = "net.tcp",
                    Host = Dns.GetHostName(),
                    Port = configuration.Port
                };
                _serviceHost.AddServiceEndpoint(typeof (ISigningServer), new NetTcpBinding
                {
                    TransferMode = TransferMode.Streamed,
                    MaxReceivedMessageSize = int.MaxValue,
                    MaxBufferSize = int.MaxValue,
                    OpenTimeout = TimeSpan.MaxValue,
                    CloseTimeout = TimeSpan.MaxValue,
                    SendTimeout = TimeSpan.MaxValue,
                    ReceiveTimeout = TimeSpan.MaxValue,
                    MaxConnections = int.MaxValue,
                }, uri.Uri);

                _serviceHost.Open();
            }
            catch (Exception e)
            {
                Log.Fatal(e, "Starting the server failed");
                Stop();
                return;
            }
        }

        public void ConsoleStop()
        {
            OnStop();
        }

        protected override void OnStop()
        {
            try
            {
                Log.Info("Stopping server");
                if (_serviceHost != null)
                {
                    _serviceHost.Close();
                }
            }
            catch (Exception e)
            {
                Log.Error(e, "Stopping server failed");
            }
        }
    }
}
