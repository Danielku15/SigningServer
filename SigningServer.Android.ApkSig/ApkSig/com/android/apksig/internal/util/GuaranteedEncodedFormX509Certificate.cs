// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

/*
 * Copyright (C) 2022 Daniel Kuschny (C# port)
 * Copyright (C) 2017 The Android Open Source Project
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
    /// {@link X509Certificate} whose {@link #getEncoded()} returns the data provided at construction
    /// time.
    /// </summary>
    public class GuaranteedEncodedFormX509Certificate: SigningServer.Android.Com.Android.Apksig.Internal.Util.DelegatingX509Certificate
    {
        internal static readonly long serialVersionUID = 1L;
        
        internal readonly byte[] mEncodedForm;
        
        internal int mHash = -1;
        
        public GuaranteedEncodedFormX509Certificate(SigningServer.Android.Security.Cert.X509Certificate wrapped, byte[] encodedForm)
            : base (wrapped)
        {
            ;
            this.mEncodedForm = (byte[])((encodedForm != null) ? encodedForm.Clone() : null);
        }
        
        public override byte[] GetEncoded()
        {
            return (byte[])((mEncodedForm != null) ? mEncodedForm.Clone() : null);
        }

        public override bool Equals(X509Certificate other)
        {
            return this.Equals((object)other);
        }

        public override bool Equals(object o)
        {
            if (this == o)
                return true;
            if (!(o is SigningServer.Android.Security.Cert.X509Certificate))
                return false;
            try
            {
                byte[] a = this.GetEncoded();
                byte[] b = ((SigningServer.Android.Security.Cert.X509Certificate)o).GetEncoded();
                return SigningServer.Android.Collections.Arrays.Equals(a, b);
            }
            catch (SigningServer.Android.Security.Cert.CertificateEncodingException e)
            {
                return false;
            }
        }
        
        public override int GetHashCode()
        {
            if (mHash == -1)
            {
                try
                {
                    mHash = SigningServer.Android.Collections.Arrays.GetHashCode(this.GetEncoded());
                }
                catch (SigningServer.Android.Security.Cert.CertificateEncodingException e)
                {
                    mHash = 0;
                }
            }
            return mHash;
        }
        
    }
    
}
