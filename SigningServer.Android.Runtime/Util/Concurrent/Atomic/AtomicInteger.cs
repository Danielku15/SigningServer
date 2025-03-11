using System.Threading;

namespace SigningServer.Android.Util.Concurrent.Atomic
{
    internal class AtomicInteger
    {
        private int _value;
        public AtomicInteger(int i)
        {
            _value = i;
        }

        public int GetAndIncrement()
        {
            return Interlocked.Increment(ref _value) - 1;
        }
    }
}
