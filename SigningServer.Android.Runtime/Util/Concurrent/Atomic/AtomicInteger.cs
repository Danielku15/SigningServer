using System.Threading;

namespace SigningServer.Android.Util.Concurrent.Atomic
{
    internal class AtomicInteger
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