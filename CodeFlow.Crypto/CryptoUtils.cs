using NSec.Cryptography;
using System;

namespace CodeFlow.Crypto
{
    public static class CryptoUtils
    {
        private static readonly SignatureAlgorithm algorithm = SignatureAlgorithm.Ed25519;

        public static byte[] Sign(Key privateKey, byte[] data)
        {
            return algorithm.Sign(privateKey, data);
        }

        public static bool Verify(byte[] publicKeyRaw, byte[] data, byte[] signature)
        {
            var pub = PublicKey.Import(algorithm, publicKeyRaw, KeyBlobFormat.RawPublicKey);
            return algorithm.Verify(pub, data, signature);
        }
    }
}
