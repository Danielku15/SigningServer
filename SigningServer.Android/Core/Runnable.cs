using System;

namespace SigningServer.Android.Core
{
    public interface Runnable
    {
        void Run();
    }    
    
    public class DelegateRunnable : Runnable
    {
        private readonly Action mRun;

        public DelegateRunnable(Action run)
        {
            mRun = run;
        }

        public void Run()
        {
            mRun();
        }
    }
}