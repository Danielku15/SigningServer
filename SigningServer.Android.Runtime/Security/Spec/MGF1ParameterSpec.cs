namespace SigningServer.Android.Security.Spec
{
    internal class MGF1ParameterSpec : AlgorithmParameterSpec
    {
        public static readonly MGF1ParameterSpec SHA1 = new MGF1ParameterSpec("SHA1");
        public static readonly MGF1ParameterSpec SHA256 = new MGF1ParameterSpec("SHA-256");
        public static readonly MGF1ParameterSpec SHA384 = new MGF1ParameterSpec("SHA-384");
        public static readonly MGF1ParameterSpec SHA512 = new MGF1ParameterSpec("SHA-512");
        
        private readonly string _digestAlgorithm;
        
        public MGF1ParameterSpec(string mdName)
        {
            _digestAlgorithm = mdName;
        }

        public string GetDigestAlgorithm()
        {
            return _digestAlgorithm;
        }
    }
}
