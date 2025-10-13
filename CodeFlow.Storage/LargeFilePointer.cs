// In file: D:\GT\Serious Projects\CodeFlow\CodeFlow.Storage\LargeFilePointer.cs

using System.Collections.Generic;
using System.Text.Json;

namespace CodeFlow.Storage // The namespace is correct for its current location
{
    public class LargeFilePointer
    {
        /// <summary>
        /// A fixed type identifier to help distinguish this object.
        /// </summary>
        public string Type { get; set; } = "lfs-pointer";

        /// <summary>
        /// The total size of the original file in bytes.
        /// </summary>
        public long TotalSize { get; set; }

        /// <summary>
        /// An ordered list of the content hashes of the file's chunks.
        /// </summary>
        public List<string> ChunkHashes { get; set; } = new List<string>();

        // --- Helper methods for serialization ---

        public string ToJson()
        {
            return JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
        }

        public static LargeFilePointer? FromJson(string json)
        {
            try
            {
                // This is where you might need to handle the old format if you have old commits
                if (!json.Contains("\"Type\"") && json.Contains("\"OriginalSize\""))
                {
                     var oldFormat = JsonSerializer.Deserialize<OldPointerFormat>(json);
                     return new LargeFilePointer { 
                         TotalSize = oldFormat.OriginalSize, 
                         ChunkHashes = oldFormat.ChunkHashes
                     };
                }
                return JsonSerializer.Deserialize<LargeFilePointer>(json);
            }
            catch
            {
                return null;
            }
        }

        // Helper class to deserialize old pointers if they exist in your repo
        private class OldPointerFormat
        {
            public long OriginalSize { get; set; }
            public List<string> ChunkHashes { get; set; } = new List<string>();
        }
    }
}