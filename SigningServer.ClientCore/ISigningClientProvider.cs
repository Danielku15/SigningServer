namespace SigningServer.ClientCore;

public interface ISigningClientProvider<TConfiguration> where TConfiguration : SigningClientConfigurationBase
{
    SigningClient<TConfiguration> CreateClient(TConfiguration configuration);
}
