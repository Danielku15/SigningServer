using System.ServiceModel;

namespace SigningServer.Contracts
{
    [ServiceContract]
    public interface ISigningServer
    {
        [OperationContract]
        string[] GetSupportedFileExtensions();
        [OperationContract]
        SignFileResponse SignFile(SignFileRequest signFileRequest);
    }
}
