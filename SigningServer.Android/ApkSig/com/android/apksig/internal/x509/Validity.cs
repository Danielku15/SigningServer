// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

using System;

namespace SigningServer.Android.Com.Android.Apksig.Internal.X509
{
    /// <summary>
    /// {@code Validity} as specified in RFC 5280.
    /// </summary>
    [SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1Class(Type = SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1Type.SEQUENCE)]
    public class Validity
    {
        [SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1Field(Index = 0, Type = SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1Type.CHOICE)]
        public SigningServer.Android.Com.Android.Apksig.Internal.X509.Time notBefore;
        
        [SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1Field(Index = 1, Type = SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1Type.CHOICE)]
        public SigningServer.Android.Com.Android.Apksig.Internal.X509.Time notAfter;
        
    }
    
}
