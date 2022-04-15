﻿using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace SigningServer.Android.Security.BouncyCastle
{
    public class BouncyCastlePrivateKey : PrivateKey
    {
        public AsymmetricKeyParameter KeyParameter { get; }

        public BouncyCastlePrivateKey(AsymmetricKeyParameter keyParameter)
        {
            KeyParameter = keyParameter;
        }

        public sbyte[] GetEncoded()
        {
            throw new KeyException("Encoding of private key not supported");
        }

        public string GetFormat()
        {
            return "X.509";
        }

        public string GetAlgorithm()
        {
            switch (KeyParameter)
            {
                case DsaKeyParameters _: return "DSA";
                case RsaKeyParameters _: return "RSA";
                case ECKeyParameters _: return "EC";
            }
            throw new KeyException("Unknown private key algorithm");
        }
    }
}