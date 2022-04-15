using SigningServer.Android.Core;

namespace SigningServer.Android.Util.Concurrent
{
    public interface ExecutorService
    {
        void ShutdownNow();
        void Execute(Runnable task);
    }
    public class ThreadPoolExecutor: ExecutorService
    {
        public ThreadPoolExecutor(int digestParallelism, int i, long l, TimeUnit milliseconds, ArrayBlockingQueue<Runnable> arrayBlockingQueue, CallerRunsPolicy callerRunsPolicy)
        {
            throw new System.NotImplementedException();
        }

        public void ShutdownNow()
        {
            throw new System.NotImplementedException();
        }

        internal class CallerRunsPolicy
        {
        }
    }
}