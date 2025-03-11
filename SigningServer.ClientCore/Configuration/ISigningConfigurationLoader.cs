using System.Threading.Tasks;

namespace SigningServer.ClientCore.Configuration;

public interface ISigningConfigurationLoader<TConfiguration> where TConfiguration : SigningClientConfigurationBase
{
    Task<TConfiguration?> LoadConfigurationAsync();
}
