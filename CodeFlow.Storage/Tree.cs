using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace CodeFlow.Storage
{
    public class Tree
    {
        public List<TreeEntry> Entries { get; set; } = new();

        private readonly JsonSerializerOptions opts = new JsonSerializerOptions { WriteIndented = false };

        public string ToJson() => JsonSerializer.Serialize(this, opts);

        public static Tree FromJson(string json) => JsonSerializer.Deserialize<Tree>(json);

        public class TreeEntry
        {
            public string Path { get; set; }
            public string Hash { get; set; }    // blob hash or subtree hash
            public string Type { get; set; }    // "blob" or "tree"
        }
    }

    public class TreeStore
    {
        private readonly BlobStore blobStore;

        public TreeStore(BlobStore blobStore)
        {
            this.blobStore = blobStore;
        }

        // Save tree JSON as blob and return its hash
        public string SaveTree(Tree tree)
        {
            var bytes = System.Text.Encoding.UTF8.GetBytes(tree.ToJson());
            return blobStore.SaveBlob(bytes);
        }

        public Tree LoadTree(string treeHash)
        {
            var bytes = blobStore.GetBlob(treeHash);
            return bytes == null ? null : Tree.FromJson(System.Text.Encoding.UTF8.GetString(bytes));
        }
    }
}
