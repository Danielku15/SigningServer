namespace SigningServer.Android.Security
{
    public interface CryptographyProvider
    {
        Signature CreateSignature(string jcaSignatureAlgorithm);
    }
    
    public interface CryptographyProviderAccessor
    {
        CryptographyProvider Provider { get; }
    }
}