/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System;
using System.Linq;
using System.Threading.Tasks;

namespace SigningServer.Android.ApkSig.Util
{
    public interface RunnablesExecutor
    {
        void execute(RunnablesProvider provider);
    }

    public class RunnablesExecutors
    {
        public static readonly RunnablesExecutor SINGLE_THREADED = new SingleThreadedRunnablesExecutor();
        public static RunnablesExecutor MULTI_THREADED = new MultiThreadedRunnablesExecutor();

        public class SingleThreadedRunnablesExecutor : RunnablesExecutor
        {
            public void execute(RunnablesProvider provider)
            {
                provider()();
            }
        }
        
        
        public class MultiThreadedRunnablesExecutor : RunnablesExecutor
        {
            private static readonly int PARALLELISM = Math.Min(32, System.Environment.ProcessorCount);
            
            public void execute(RunnablesProvider provider)
            {
                var tasks = Enumerable.Range(0, PARALLELISM)
                    .Select(i => Task.Run(() => provider()()));
                Task.WaitAll(tasks.ToArray());
            }
        }
    }

}