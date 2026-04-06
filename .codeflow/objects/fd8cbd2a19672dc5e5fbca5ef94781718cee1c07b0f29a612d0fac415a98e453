using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CodeFlow.Storage
{
    public class ContentAddressableStore
    {
        private readonly string storePath;
        private readonly string headFile;
        // This is the crucial fix for the BOM issue. It's a UTF-8 encoder that does NOT write the BOM.
        private static readonly Encoding Utf8NoBom = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

        public ContentAddressableStore(string path)
        {
            storePath = path;
            Directory.CreateDirectory(storePath);
            headFile = Path.Combine(Path.GetDirectoryName(storePath) ?? ".codeflow", "HEAD");
        }

        // This method saves string content (like commits and trees)
        public string SaveObject(string content)
        {
            var hash = ComputeHash(content);
            var filePath = GetPathFromHash(hash);
            // FIX: Use the Utf8NoBom encoding here to prevent the BOM from being written.
            File.WriteAllText(filePath, content, Utf8NoBom);
            return hash;
        }

        // This method saves raw byte content (like blobs from a remote)
        public void SaveObject(byte[] data, string hash)
        {
            var path = GetPathFromHash(hash);
            // FIX: Use WriteAllBytes for byte arrays. 'content' did not exist and this is the correct method.
            File.WriteAllBytes(path, data);
        }

        // FIX: Return type is now string? to indicate it can be null.
        public string? GetObject(string hash)
        {
            var filePath = GetPathFromHash(hash);
            return File.Exists(filePath) ? File.ReadAllText(filePath, Encoding.UTF8) : null;
        }

        private string ComputeHash(string content)
        {
            using var sha = SHA256.Create();
            var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(content));
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        public void UpdateHead(string hash)
        {
            var dir = Path.GetDirectoryName(headFile);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);
            File.WriteAllText(headFile, hash, Utf8NoBom); // Also use NoBOM for the HEAD file for consistency
        }

        // FIX: Return type is now string? to indicate it can be null.
        public string? ReadHead()
        {
            return File.Exists(headFile) ? File.ReadAllText(headFile).Trim() : null;
        }

        public bool HasObject(string hash)
        {
            var path = GetPathFromHash(hash);
            return File.Exists(path);
        }

        // FIX: Added the missing helper method to centralize path creation.
        private string GetPathFromHash(string hash)
        {
            return Path.Combine(storePath, hash);
        }
        public byte[]? GetRawObject(string hash)
        {
            var path = GetPathFromHash(hash);
            if (!File.Exists(path))
                return null;

            return File.ReadAllBytes(path);
        }

    }
}
