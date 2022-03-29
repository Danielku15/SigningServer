/*
 * Copyright (C) 2016 The Android Open Source Project
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
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace SigningServer.Android.ApkSig.Internal.Util
{
    /**
     * Inclusive interval of integers.
     */
    public class InclusiveIntRange
    {
        private readonly int min;
        private readonly int max;

        private InclusiveIntRange(int min, int max)
        {
            this.min = min;
            this.max = max;
        }

        public int getMin()
        {
            return min;
        }

        public int getMax()
        {
            return max;
        }

        public static InclusiveIntRange fromTo(int min, int max)
        {
            return new InclusiveIntRange(min, max);
        }

        public static InclusiveIntRange from(int min)
        {
            return new InclusiveIntRange(min, int.MaxValue);
        }

        public List<InclusiveIntRange> getValuesNotIn(
            List<InclusiveIntRange> sortedNonOverlappingRanges)
        {
            if (sortedNonOverlappingRanges.Count == 0)
            {
                return new List<InclusiveIntRange>
                {
                    this
                };
            }

            int testValue = min;
            List<InclusiveIntRange> result = null;
            foreach (InclusiveIntRange range in
                     sortedNonOverlappingRanges)
            {
                int rangeMax = range.max;
                if (testValue > rangeMax)
                {
                    continue;
                }

                int rangeMin = range.min;
                if (testValue < range.min)
                {
                    if (result == null)
                    {
                        result = new List<InclusiveIntRange>();
                    }

                    result.Add(fromTo(testValue, rangeMin - 1));
                }

                if (rangeMax >= max)
                {
                    return (result != null) ? result : new List<InclusiveIntRange>();
                }

                testValue = rangeMax + 1;
            }

            if (testValue <= max)
            {
                if (result == null)
                {
                    result = new List<InclusiveIntRange>(1);
                }

                result.Add(fromTo(testValue, max));
            }

            return (result != null) ? result : new List<InclusiveIntRange>();
        }


        public String toString()
        {
            return "[" + min + ", " + ((max < int.MaxValue) ? (max + "]") : "\u221e)");
        }
    }
}