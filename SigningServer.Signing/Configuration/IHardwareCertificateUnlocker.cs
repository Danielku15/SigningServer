namespace SigningServer.Signing.Configuration;

public interface IHardwareCertificateUnlocker
{
    void RegisterForUpdate(CertificateConfiguration certificateConfiguration);
}
