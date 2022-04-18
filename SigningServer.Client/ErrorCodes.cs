namespace SigningServer.Client;

internal static class ErrorCodes
{
    public const int UnexpectedError = 1;
    public const int FileNotFound = 2;
    public const int FileAlreadySigned = 3;
    public const int UnsupportedFileFormat = 4;
    public const int Unauthorized = 5;
    public const int InvalidConfiguration = 6;

    public const int CommunicationError = 7;
    // public const int SecurityNegotiationFailed = 8; -> Phased out
}
