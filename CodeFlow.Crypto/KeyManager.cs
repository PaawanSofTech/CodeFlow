using NSec.Cryptography;
using System;
using System.IO;
using System.Text;

namespace CodeFlow.Crypto
{
    public static class KeyManager
    {
        private const string KeyFileName = ".codeflow/keys/private.key";
        private const string PubFileName = ".codeflow/keys/public.key";
        private static readonly SignatureAlgorithm Algorithm = SignatureAlgorithm.Ed25519;

        public static void EnsureKeysDirectory()
        {
            Directory.CreateDirectory(Path.GetDirectoryName(KeyFileName));
        }

        public static (byte[] privateRaw, byte[] publicRaw) GenerateAndSaveKeyPair()
        {
            EnsureKeysDirectory();

            var creation = new KeyCreationParameters
            {
                ExportPolicy = KeyExportPolicies.AllowPlaintextExport
            };

            using var key = new Key(Algorithm, creation);
            var privateRaw = key.Export(KeyBlobFormat.RawPrivateKey);
            var publicRaw = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);

            File.WriteAllBytes(KeyFileName, privateRaw);
            File.WriteAllBytes(PubFileName, publicRaw);

            return (privateRaw, publicRaw);
        }

        public static bool KeysExist()
        {
            return File.Exists(KeyFileName) && File.Exists(PubFileName);
        }

        public static (byte[] privateRaw, byte[] publicRaw) LoadKeyPair()
        {
            var priv = File.ReadAllBytes(KeyFileName);
            var pub = File.ReadAllBytes(PubFileName);
            return (priv, pub);
        }

        public static byte[] GetPublicKeyFromStored()
        {
            var pub = File.ReadAllBytes(PubFileName);
            return pub;
        }

        public static Key ImportPrivateKey(byte[] rawPrivate)
        {
            // Caller should dispose the returned Key when done
            return Key.Import(Algorithm, rawPrivate, KeyBlobFormat.RawPrivateKey);
        }

        public static PublicKey ImportPublicKey(byte[] rawPublic)
        {
            return PublicKey.Import(Algorithm, rawPublic, KeyBlobFormat.RawPublicKey);
        }
    }
}
