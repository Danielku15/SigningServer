using System;

namespace SigningServer.Android
{
    [AttributeUsage(AttributeTargets.Method)]
    public class TestAttribute : Attribute
    {
        public Type Expected { get; set; }
        
    }
}