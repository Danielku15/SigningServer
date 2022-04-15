using System.Threading;

namespace SigningServer.Android.Util.Concurrent.Atomic
{
    public struct AtomicInteger
    {
        private int mValue;
        public AtomicInteger(int i)
        {
            mValue = i;
        }

        public int GetAndIncrement()
        {
            return Interlocked.Increment(ref mValue) - 1;
        }
    }
}