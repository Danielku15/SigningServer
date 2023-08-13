using System.Threading.Tasks;

namespace SigningServer.StandaloneClient;

internal interface ISigningConfigurationLoader
{
    Task<SigningClientConfiguration?> LoadConfigurationAsync();
}
