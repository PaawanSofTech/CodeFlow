// In file: D:\GT\Serious Projects\CodeFlow\CodeFlow.Storage\Chunker.cs

using System;
using System.IO;

namespace CodeFlow.Storage
{
    public class Chunker
    {
        private readonly BlobStore _blobStore;
        private readonly int _chunkSize = 4 * 1024 * 1024; // default 4MB

        public Chunker(BlobStore blobStore)
        {
            _blobStore = blobStore;
        }

        public LargeFilePointer SaveLargeFile(string filePath)
        {
            // --- THIS IS THE PART THAT WAS FIXED ---
            var pointer = new LargeFilePointer
            {
                // We now use "TotalSize" to match the updated class definition.
                TotalSize = new FileInfo(filePath).Length
            };
            // The 'Type' property is set by default in the LargeFilePointer class itself.
            // --- END OF FIX ---

            using var fs = File.OpenRead(filePath);
            var buffer = new byte[_chunkSize];
            int read;
            while ((read = fs.Read(buffer, 0, buffer.Length)) > 0)
            {
                var chunkData = buffer;
                if (read < _chunkSize)
                {
                    // For the last chunk, create a smaller array to avoid storing extra zeros
                    chunkData = new byte[read];
                    Array.Copy(buffer, chunkData, read);
                }
                
                var hash = _blobStore.SaveBlob(chunkData);
                pointer.ChunkHashes.Add(hash);
            }

            return pointer;
        }

        public void RestoreLargeFile(LargeFilePointer ptr, string targetPath)
        {
            using var fs = File.Create(targetPath);
            foreach (var hash in ptr.ChunkHashes)
            {
                var bytes = _blobStore.GetBlob(hash);
                if (bytes == null) throw new Exception($"Missing chunk {hash} for file {targetPath}");
                fs.Write(bytes, 0, bytes.Length);
            }
        }
    }
}