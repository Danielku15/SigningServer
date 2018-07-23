using System;
using System.IO;
using System.Linq;
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
                
                // Setup without transport security (new mode)
                var uri = new UriBuilder
                {
                    Scheme = "net.tcp",
                    Host = Dns.GetHostName(),
                    Port = configuration.Port
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
                    PortSharingEnabled = false,
                };
                binding.Security.Mode = SecurityMode.None;
                var endPoint = _serviceHost.AddServiceEndpoint(typeof(ISigningServer), binding, uri.Uri);
                endPoint.Behaviors.Add(new AddClientMessageInspectorBehavior());

                // Setup without transport security (new mode)
                uri.Port = configuration.LegacyPort;
                var legacyBinding = new NetTcpBinding
                {
                    TransferMode = TransferMode.Streamed,
                    MaxReceivedMessageSize = int.MaxValue,
                    MaxBufferSize = int.MaxValue,
                    OpenTimeout = TimeSpan.FromMinutes(5),
                    CloseTimeout = TimeSpan.FromMinutes(5),
                    SendTimeout = TimeSpan.FromMinutes(60),
                    ReceiveTimeout = TimeSpan.FromMinutes(60),
                    MaxConnections = int.MaxValue,
                    PortSharingEnabled = false,
                };
                var legacyEndpoint = _serviceHost.AddServiceEndpoint(typeof(ISigningServer), legacyBinding, uri.Uri);
                legacyEndpoint.Behaviors.Add(new AddClientMessageInspectorBehavior());
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
