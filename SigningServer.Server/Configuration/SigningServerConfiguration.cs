namespace SigningServer.Server.Configuration
{
    public class SigningServerConfiguration
    {
        public int Port { get; set; }
        public string TimestampServer { get; set; }
        public string WorkingDirectory { get; set; }
        public CertificateConfiguration[] Certificates { get; set; }
    }
}
