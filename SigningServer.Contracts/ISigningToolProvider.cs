namespace SigningServer.Contracts
{
    public interface ISigningToolProvider
    {
        ISigningTool GetSigningTool(string fileName);
        string[] GetSupportedFileExtensions();
    }
}