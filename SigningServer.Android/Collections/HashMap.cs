using System.Collections.Generic;

namespace SigningServer.Android.Collections
{
    public class HashMap<TKey, TValue> : Dictionary<TKey, TValue>,  Map<TKey, TValue>
    {
        public HashMap()
        {
        }

        public HashMap(int capacity) : base(capacity)
        {
            
        }
        public Set<MapEntry<object, object>> EntrySet()
        {
            throw new System.NotImplementedException();
        }

        
        public bool IsEmpty()
        {
            throw new System.NotImplementedException();
        }
        
    }
}