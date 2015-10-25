using SigningServer.Contracts;

namespace SigningServer.Server
{
    public interface ISigningToolProvider
    {
        ISigningTool GetSigningTool(string fileName);
        string[] GetSupportedFileExtensions();
    }
}