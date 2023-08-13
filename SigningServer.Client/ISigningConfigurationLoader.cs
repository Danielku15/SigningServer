using System.Threading.Tasks;

namespace SigningServer.Client;

internal interface ISigningConfigurationLoader
{
    Task<SigningClientConfiguration?> LoadConfigurationAsync();
}
