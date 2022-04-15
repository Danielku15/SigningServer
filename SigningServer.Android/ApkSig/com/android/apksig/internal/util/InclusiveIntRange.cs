// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

using System;

namespace SigningServer.Android.Com.Android.Apksig.Internal.Util
{
    /// <summary>
    /// Inclusive interval of integers.
    /// </summary>
    public class InclusiveIntRange
    {
        internal readonly int min;
        
        internal readonly int max;
        
        internal InclusiveIntRange(int min, int max)
        {
            this.min = min;
            this.max = max;
        }
        
        public virtual int GetMin()
        {
            return min;
        }
        
        public virtual int GetMax()
        {
            return max;
        }
        
        public static SigningServer.Android.Com.Android.Apksig.Internal.Util.InclusiveIntRange FromTo(int min, int max)
        {
            return new SigningServer.Android.Com.Android.Apksig.Internal.Util.InclusiveIntRange(min, max);
        }
        
        public static SigningServer.Android.Com.Android.Apksig.Internal.Util.InclusiveIntRange From(int min)
        {
            return new SigningServer.Android.Com.Android.Apksig.Internal.Util.InclusiveIntRange(min, SigningServer.Android.Core.IntExtensions.MAX_VALUE);
        }
        
        public virtual SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Util.InclusiveIntRange> GetValuesNotIn(SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Util.InclusiveIntRange> sortedNonOverlappingRanges)
        {
            if (sortedNonOverlappingRanges.IsEmpty())
            {
                return SigningServer.Android.Util.Collections.SingletonList<SigningServer.Android.Com.Android.Apksig.Internal.Util.InclusiveIntRange>(this);
            }
            int testValue = min;
            SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Util.InclusiveIntRange> result = null;
            foreach (SigningServer.Android.Com.Android.Apksig.Internal.Util.InclusiveIntRange range in sortedNonOverlappingRanges)
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
                        result = new SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Util.InclusiveIntRange>();
                    }
                    result.Add(SigningServer.Android.Com.Android.Apksig.Internal.Util.InclusiveIntRange.FromTo(testValue, rangeMin - 1));
                }
                if (rangeMax >= max)
                {
                    return (result != null) ? result : SigningServer.Android.Util.Collections.EmptyList<SigningServer.Android.Com.Android.Apksig.Internal.Util.InclusiveIntRange>();
                }
                testValue = rangeMax + 1;
            }
            if (testValue <= max)
            {
                if (result == null)
                {
                    result = new SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Util.InclusiveIntRange>(1);
                }
                result.Add(SigningServer.Android.Com.Android.Apksig.Internal.Util.InclusiveIntRange.FromTo(testValue, max));
            }
            return (result != null) ? result : SigningServer.Android.Util.Collections.EmptyList<SigningServer.Android.Com.Android.Apksig.Internal.Util.InclusiveIntRange>();
        }
        
        public override string ToString()
        {
            return "[" + min + ", " + ((max < SigningServer.Android.Core.IntExtensions.MAX_VALUE) ? (max + "]") : "\u221e)");
        }
        
    }
    
}
