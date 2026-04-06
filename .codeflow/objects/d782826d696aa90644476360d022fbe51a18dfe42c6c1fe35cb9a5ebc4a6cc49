using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace CodeFlow.Storage
{
    public class Index
    {
        private readonly string indexPath;
        private readonly JsonSerializerOptions opts = new JsonSerializerOptions { WriteIndented = false };

        public Index(string repoRoot)
        {
            Directory.CreateDirectory(Path.Combine(repoRoot, ".codeflow"));
            indexPath = Path.Combine(repoRoot, ".codeflow", "index");
        }

        public Dictionary<string, string> Load()
        {
            if (!File.Exists(indexPath)) return new Dictionary<string, string>();
            var json = File.ReadAllText(indexPath);
            return JsonSerializer.Deserialize<Dictionary<string, string>>(json) ?? new();
        }

        public void Save(Dictionary<string, string> map)
        {
            var json = JsonSerializer.Serialize(map, opts);
            File.WriteAllText(indexPath, json);
        }

        public void AddOrUpdate(string path, string blobHash)
        {
            var m = Load();
            m[path] = blobHash;
            Save(m);
        }

        public void Clear()
        {
            Save(new Dictionary<string, string>());
        }
    }
    
}
