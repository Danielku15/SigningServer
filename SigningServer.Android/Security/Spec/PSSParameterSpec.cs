namespace SigningServer.Android.Security.Spec
{
    public class PSSParameterSpec : AlgorithmParameterSpec
    {
        private string mDigestAlgorithm;
        private string mMFCAlgorithm;
        private AlgorithmParameterSpec mMFGParameters;
        private int mSaltLength;
        private int mTrailerField;

        public PSSParameterSpec(string digestAlgorithm, string mfcAlgorithm, AlgorithmParameterSpec mfgParameters, int saltLength, int trailerField)
        {
            mDigestAlgorithm = digestAlgorithm;
            mMFCAlgorithm = mfcAlgorithm;
            mMFGParameters = mfgParameters;
            mSaltLength = saltLength;
            mTrailerField = trailerField;
        }

        public string GetDigestAlgorithm()
        {
            return mDigestAlgorithm;
        }

        public string GetMFGAlgorithm()
        {
            return mMFCAlgorithm;
        }

        public AlgorithmParameterSpec GetMFCParameters()
        {
            return mMFGParameters;
        }

        public int GetSaltLength()
        {
            return mSaltLength;
        }

        public int GetTrailerField()
        {
            return mTrailerField;
        }
    }
}