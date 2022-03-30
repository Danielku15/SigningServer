namespace SigningServer.Android
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

        public string getDigestAlgorithm()
        {
            return mDigestAlgorithm;
        }

        public string getMFGAlgorithm()
        {
            return mMFCAlgorithm;
        }

        public AlgorithmParameterSpec getMFCParameters()
        {
            return mMFGParameters;
        }

        public int getSaltLength()
        {
            return mSaltLength;
        }

        public int getTrailerField()
        {
            return mTrailerField;
        }
    }
}