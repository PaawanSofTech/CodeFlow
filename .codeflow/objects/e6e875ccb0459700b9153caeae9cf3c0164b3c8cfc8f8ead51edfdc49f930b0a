using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
namespace CodeFlow.Crypto
{
    public static class Hash
    {
        // This method determines the object type from its content.
        // It's a heuristic based on JSON properties.
        public static string GetObjectType(string objectContent)
        {
            if (objectContent.Contains("\"parentHash\"") && objectContent.Contains("\"treeHash\""))
            {
                return "commit";
            }
            if (objectContent.Contains("\"entries\""))
            {
                return "tree";
            }
            return "blob";
        }

        // A generic SHA256 hash computation for a byte array
        public static string ComputeHash(byte[] data)
        {
            using var sha = SHA256.Create();
            var hashBytes = sha.ComputeHash(data);
            return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
        }
    }
}