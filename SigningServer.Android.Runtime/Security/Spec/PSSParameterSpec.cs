namespace SigningServer.Android.Security.Spec
{
    internal class PSSParameterSpec : AlgorithmParameterSpec
    {
        private readonly string _digestAlgorithm;
        private readonly string _mfcAlgorithm;
        private readonly AlgorithmParameterSpec _mfgParameters;
        private readonly int _saltLength;
        private readonly int _trailerField;

        public PSSParameterSpec(string digestAlgorithm, string mfcAlgorithm, AlgorithmParameterSpec mfgParameters, int saltLength, int trailerField)
        {
            _digestAlgorithm = digestAlgorithm;
            _mfcAlgorithm = mfcAlgorithm;
            _mfgParameters = mfgParameters;
            _saltLength = saltLength;
            _trailerField = trailerField;
        }

        public string GetDigestAlgorithm()
        {
            return _digestAlgorithm;
        }

        public string GetMFGAlgorithm()
        {
            return _mfcAlgorithm;
        }

        public AlgorithmParameterSpec GetMFCParameters()
        {
            return _mfgParameters;
        }

        public int GetSaltLength()
        {
            return _saltLength;
        }

        public int GetTrailerField()
        {
            return _trailerField;
        }
    }
}
