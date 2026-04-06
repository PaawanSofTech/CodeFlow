using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CodeFlow.Storage
{
    public class BlobStore
    {
        private readonly string objectsPath;

        public BlobStore(string objectsPath)
        {
            this.objectsPath = objectsPath;
            Directory.CreateDirectory(objectsPath);
        }

        public string SaveBlob(byte[] content)
        {
            var hash = ComputeHash(content);
            var path = Path.Combine(objectsPath, hash);
            if (!File.Exists(path))
                File.WriteAllBytes(path, content);
            return hash;
        }

        public byte[] GetBlob(string hash)
        {
            var path = Path.Combine(objectsPath, hash);
            return File.Exists(path) ? File.ReadAllBytes(path) : null;
        }

        private static string ComputeHash(byte[] content)
        {
            using var sha = SHA256.Create();
            var h = sha.ComputeHash(content);
            return BitConverter.ToString(h).Replace("-", "").ToLowerInvariant();
        }
    }
}
