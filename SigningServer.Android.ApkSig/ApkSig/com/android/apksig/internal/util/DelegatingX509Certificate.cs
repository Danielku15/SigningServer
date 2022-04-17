// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

/*
 * Copyright (C) 2022 Daniel Kuschny (C# port)
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
using SigningServer.Android.Security.Cert;

namespace SigningServer.Android.Com.Android.Apksig.Internal.Util
{
    /// <summary>
    /// {@link X509Certificate} which delegates all method invocations to the provided delegate
    /// {@code X509Certificate}.
    /// </summary>
    public class DelegatingX509Certificate: SigningServer.Android.Security.Cert.X509Certificate
    {
        internal static readonly long serialVersionUID = 1L;
        
        internal readonly SigningServer.Android.Security.Cert.X509Certificate mDelegate;
        
        public DelegatingX509Certificate(SigningServer.Android.Security.Cert.X509Certificate @delegate)
        {
            this.mDelegate = @delegate;
        }
        
        public override bool HasUnsupportedCriticalExtension()
        {
            return mDelegate.HasUnsupportedCriticalExtension();
        }
        
        public override SigningServer.Android.Math.BigInteger GetSerialNumber()
        {
            return mDelegate.GetSerialNumber();
        }
        
        public override SigningServer.Android.Security.Principal GetIssuerDN()
        {
            return mDelegate.GetIssuerDN();
        }
        
        public override SigningServer.Android.Security.Principal GetSubjectDN()
        {
            return mDelegate.GetSubjectDN();
        }
        
        public override bool[] GetKeyUsage()
        {
            return mDelegate.GetKeyUsage();
        }
        
        public override  byte[] GetEncoded()
        {
            return mDelegate.GetEncoded();
        }
        
        public override string ToString()
        {
            return mDelegate.ToString();
        }
        
        public override SigningServer.Android.Security.PublicKey GetPublicKey()
        {
            return mDelegate.GetPublicKey();
        }
        
        public override X500Principal GetIssuerX500Principal()
        {
            return mDelegate.GetIssuerX500Principal();
        }
    }
}
