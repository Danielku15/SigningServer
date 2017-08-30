using System.ServiceModel;

namespace SigningServer.Contracts
{
    [ServiceContract]
    public interface ISigningServer
    {
        [OperationContract]
        string[] GetSupportedFileExtensions();
        [OperationContract]
        string[] GetSupportedHashAlgorithms();
        [OperationContract]
        SignFileResponse SignFile(SignFileRequest signFileRequest);
    }
}
