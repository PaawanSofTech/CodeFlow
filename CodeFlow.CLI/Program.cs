using System;
using System.IO;
using System.Linq;
using System.Text;
using CodeFlow.Storage;
using CodeFlow.Core;
using CodeFlow.Crypto;
using NSec.Cryptography;
using System.Collections.Generic;
using Minio.Exceptions;
using System.Threading.Tasks;
using System.Threading;

class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("CodeFlow CLI");

        if (args.Length == 0)
        {
            PrintHelp();
            return;
        }

        switch (args[0])
        {
            case "init":
                HandleInit();
                break;
            case "keygen":
                HandleKeyGen();
                break;
            case "add":
                HandleAdd(args.Skip(1).ToArray());
                break;
            case "commit":
                HandleCommit(args.Skip(1).ToArray());
                break;
            case "checkout":
                HandleCheckout(args.Skip(1).ToArray());
                break;
            case "log":
                HandleLog();
                break;
            case "verify":
                if (args.Length < 2) { Console.WriteLine("Usage: codeflow verify <commit-hash>"); return; }
                HandleVerify(args[1]);
                break;
            case "remote":
                HandleRemote(args.Skip(1).ToArray());
                break;
            case "push":
                if (args.Length < 2) { Console.WriteLine("Usage: codeflow push <remote>"); return; }
                await HandlePush(args[1]);
                break;
            case "pull":
                if (args.Length < 2) { Console.WriteLine("Usage: codeflow pull <remote>"); return; }
                HandlePull(args[1]);
                break;

            default:
                PrintHelp();
                break;
        }
    }

    /// <summary>
    /// Determines if the given byte array likely contains binary data
    /// that shouldn't be parsed as UTF-8 text/JSON.
    /// </summary>
    private static bool IsBinaryData(byte[] data)
    {
        if (data == null || data.Length == 0) return false;

        // Quick JSON detection: if it starts with '{', it's probably JSON text
        if (data.Length > 0 && data[0] == '{') return false;

        // Check for UTF-8 BOM (text)
        if (data.Length >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF)
            return false;

        // Check for common binary file signatures
        if (data.Length >= 2)
        {
            // PE executable (Windows .exe/.dll)
            if (data[0] == 0x4D && data[1] == 0x5A) return true; // "MZ" header

            // ELF executable (Linux)
            if (data.Length >= 4 && data[0] == 0x7F && data[1] == 0x45 && data[2] == 0x4C && data[3] == 0x46) return true;

            // Other binary formats
            if (data[0] == 0xFF && data[1] == 0xD8) return true; // JPEG
            if (data[0] == 0x89 && data[1] == 0x50) return true; // PNG
            if (data[0] == 0x50 && data[1] == 0x4B) return true; // ZIP/Office docs
        }

        // Heuristic: if more than 20% of bytes are non-printable, it's likely binary
        int sampleSize = Math.Min(256, data.Length);
        int nonPrintableCount = 0;

        for (int i = 0; i < sampleSize; i++)
        {
            byte b = data[i];
            if (b < 32 && b != 9 && b != 10 && b != 13) // Not tab, LF, or CR
            {
                nonPrintableCount++;
            }
            else if (b > 126)
            {
                nonPrintableCount++;
            }
        }

        return (double)nonPrintableCount / sampleSize > 0.20;
    }

    /// <summary>
    /// Helper method to enqueue child objects from a parsed object's content
    /// </summary>
    private static void EnqueueChildren(string content, Queue<string> queue)
    {
        var type = Hash.GetObjectType(content);

        if (type == "commit")
        {
            var c = Commit.FromJson(content);
            if (!string.IsNullOrEmpty(c.ParentHash)) queue.Enqueue(c.ParentHash);
            if (!string.IsNullOrEmpty(c.TreeHash)) queue.Enqueue(c.TreeHash);
        }
        else if (type == "tree")
        {
            var t = Tree.FromJson(content);
            foreach (var e in t.Entries)
                if (!string.IsNullOrEmpty(e.Hash)) queue.Enqueue(e.Hash);
        }
        else if (content.Contains("ChunkHashes") && content.Contains("TotalSize"))
        {
            var ptr = LargeFilePointer.FromJson(content);
            foreach (var ch in ptr.ChunkHashes) queue.Enqueue(ch);
        }
    }

    /// <summary>
    /// Gets the set of object hashes that exist on the remote by checking remote storage.
    /// This is more efficient than downloading everything to check what exists.
    /// </summary>
    private static HashSet<string> GetObjectHistorySet(string? startHash, ContentAddressableStore store)
{
    var historySet = new HashSet<string>();
    if (string.IsNullOrEmpty(startHash) || !store.HasObject(startHash))
    {
        return historySet;
    }

    var queue = new Queue<string>();
    // Use the store passed into the function, not a new BlobStore
    // var blobStore = new BlobStore(".codeflow/objects");

    queue.Enqueue(startHash);
    historySet.Add(startHash);

    while (queue.Any())
    {
        var hash = queue.Dequeue();
        
        // Use the store's method to get raw bytes
        var objBytes = store.GetRawObject(hash);
        if (objBytes == null) continue;

        // Smart traversal: We only try to parse objects that are NOT binary.
        // Binary chunks and blobs are added to the set but have no children, so we don't need to process them further.
        if (IsBinaryData(objBytes))
        {
            // This is a chunk or a binary blob. It's already in the historySet.
            // It has no children to parse, so we can safely continue.
            continue;
        }

        // It's likely a text-based object (Commit, Tree, Pointer)
        string content;
        try 
        { 
            content = Encoding.UTF8.GetString(objBytes); 
        }
        catch 
        { 
            // Failed to decode as text, treat as an opaque blob.
            continue; 
        }

        var type = Hash.GetObjectType(content);
        
        if (type == "commit")
        {
            var c = Commit.FromJson(content);
            if (!string.IsNullOrEmpty(c.ParentHash) && historySet.Add(c.ParentHash))
            {
                queue.Enqueue(c.ParentHash);
            }
            if (!string.IsNullOrEmpty(c.TreeHash) && historySet.Add(c.TreeHash))
            {
                queue.Enqueue(c.TreeHash);
            }
        }
        else if (type == "tree")
        {
            var t = Tree.FromJson(content);
            foreach (var e in t.Entries)
            {
                if (!string.IsNullOrEmpty(e.Hash) && historySet.Add(e.Hash))
                {
                    queue.Enqueue(e.Hash);
                }
            }
        }
        // This check is more robust than just string matching.
        else if (type == "lfs-pointer") 
        {
            try
            {
                var ptr = LargeFilePointer.FromJson(content);
                foreach (var chunkHash in ptr.ChunkHashes)
                {
                    // This is the crucial part. We add the chunk hashes to the set
                    // so they are included in the final result.
                    if (!string.IsNullOrEmpty(chunkHash) && historySet.Add(chunkHash))
                    {
                        // We still enqueue them to ensure the while loop completes,
                        // even though we know they'll be skipped by the IsBinaryData check.
                        queue.Enqueue(chunkHash);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Warning] Failed to parse large file pointer {hash}: {ex.Message}");
            }
        }
    }
    return historySet;
}

    // In Program.cs, REPLACE the ENTIRE HandlePush method with this one.
    static async Task HandlePush(string remoteName)
    {
        var cfg = CodeFlow.Core.RepoConfig.Load(Directory.GetCurrentDirectory());
        var remote = cfg.Remotes.FirstOrDefault(r => r.Name == remoteName);
        if (remote == null) { Console.WriteLine($"Remote '{remoteName}' not found."); return; }

        var localStore = new CodeFlow.Storage.ContentAddressableStore(".codeflow/objects");
        var minio = new CodeFlow.Storage.MinioStorageProvider(remote.Url, remote.Bucket, remote.AccessKey, remote.SecretKey);

        var localHeadHash = localStore.ReadHead();
        if (string.IsNullOrEmpty(localHeadHash))
        {
            Console.WriteLine("No local commits to push.");
            return;
        }

        Console.WriteLine("Enumerating local objects...");
        var localObjects = GetObjectHistorySet(localHeadHash, localStore);
        Console.WriteLine($"Found {localObjects.Count} local objects reachable from HEAD.");

        Console.WriteLine("Fetching remote object list...");
        var remoteObjects = await minio.ListAllObjectKeysAsync();
        Console.WriteLine($"Remote reports {remoteObjects.Count} existing objects.");

        var objectsToUpload = localObjects.Except(remoteObjects).ToList();

        if (objectsToUpload.Count == 0)
        {
            string remoteHeadHash = "";
            try
            {
                var headBytes = await minio.DownloadObjectAsync(".codeflow/HEAD");
                if (headBytes != null) remoteHeadHash = Encoding.UTF8.GetString(headBytes);
            }
            catch { /* HEAD doesn't exist or other error, that's fine */ }

            if (localHeadHash == remoteHeadHash)
            {
                Console.WriteLine("Remote is already up-to-date.");
                return;
            }
        }

        Console.WriteLine($"Uploading {objectsToUpload.Count} new objects to '{remoteName}'...");
        int uploadCount = 0;

        await Parallel.ForEachAsync(objectsToUpload, async (hash, token) =>
        {
            var localBytes = localStore.GetRawObject(hash);
            if (localBytes == null)
            {
                Console.WriteLine($"[Error] Local object {hash} not found, skipping upload.");
                return;
            }

            try
            {
                await minio.UploadObjectAsync(hash, new MemoryStream(localBytes));
                Interlocked.Increment(ref uploadCount);
                Console.WriteLine($"  - Uploaded {hash.Substring(0, 12)}... ({localBytes.Length} bytes)");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Error] Failed to upload {hash}: {ex.Message}");
            }
        });

        Console.WriteLine("Updating remote HEAD...");
        await minio.UploadObjectAsync(".codeflow/HEAD", new MemoryStream(Encoding.UTF8.GetBytes(localHeadHash)));
        Console.WriteLine($"Push complete. Uploaded {uploadCount} new objects. Remote HEAD is now {localHeadHash.Substring(0, 12)}.");
    }

    /// <summary>
    /// Simple method to get list of objects that actually exist on remote
    /// </summary>
    private static HashSet<string> GetSimpleRemoteObjectList(MinioStorageProvider minio)
    {
        var remoteObjects = new HashSet<string>();
        try
        {
            // This is a simplified approach - in a real implementation you'd use minio.ListObjectsAsync
            // For now, we'll assume remote is mostly empty and let the upload logic handle duplicates

            // You could implement actual object listing here if MinioStorageProvider supports it
            // For debugging purposes, let's assume remote has very few objects
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Warning] Could not list remote objects: {ex.Message}");
        }
        return remoteObjects;
    }

    /// <summary>
    /// Traverses the object graph starting from a given commit hash and returns a
    /// HashSet containing all reachable object hashes. This is used to efficiently
    /// determine which objects the remote repository already possesses.
    /// </summary>
    // private static HashSet<string> GetObjectHistorySet(string? startHash, ContentAddressableStore store)
    // {
    //     var historySet = new HashSet<string>();
    //     if (string.IsNullOrEmpty(startHash) || !store.HasObject(startHash))
    //     {
    //         return historySet;
    //     }

    //     var blobStore = new BlobStore(".codeflow/objects");
    //     var queue = new Queue<string>();
    //     queue.Enqueue(startHash);
    //     historySet.Add(startHash);

    //     while (queue.Any())
    //     {
    //         var hash = queue.Dequeue();

    //         var objBytes = blobStore.GetBlob(hash);
    //         if (objBytes == null) continue;

    //         // Skip binary data - no children to process
    //         if (IsBinaryData(objBytes))
    //         {
    //             continue;
    //         }

    //         string content;
    //         try
    //         {
    //             content = Encoding.UTF8.GetString(objBytes);
    //         }
    //         catch
    //         {
    //             continue;
    //         }

    //         var type = Hash.GetObjectType(content);
    //         if (type == "commit")
    //         {
    //             var c = Commit.FromJson(content);
    //             if (!string.IsNullOrEmpty(c.ParentHash) && historySet.Add(c.ParentHash))
    //             {
    //                 queue.Enqueue(c.ParentHash);
    //             }
    //             if (!string.IsNullOrEmpty(c.TreeHash) && historySet.Add(c.TreeHash))
    //             {
    //                 queue.Enqueue(c.TreeHash);
    //             }
    //         }
    //         else if (type == "tree")
    //         {
    //             var t = Tree.FromJson(content);
    //             foreach (var e in t.Entries)
    //             {
    //                 if (!string.IsNullOrEmpty(e.Hash) && historySet.Add(e.Hash))
    //                 {
    //                     queue.Enqueue(e.Hash);
    //                 }
    //             }
    //         }
    //         else if (content.Contains("ChunkHashes"))
    //         {
    //             try
    //             {
    //                 var ptr = LargeFilePointer.FromJson(content);
    //                 foreach (var chunkHash in ptr.ChunkHashes)
    //                 {
    //                     if (!string.IsNullOrEmpty(chunkHash) && historySet.Add(chunkHash))
    //                     {
    //                         queue.Enqueue(chunkHash);
    //                     }
    //                 }
    //             }
    //             catch (Exception ex)
    //             {
    //                 Console.WriteLine($"[Warning] Failed to parse large file pointer {hash}: {ex.Message}");
    //             }
    //         }
    //     }
    //     return historySet;
    // }

    static void PrintHelp()
    {
        Console.WriteLine("Usage: codeflow <command>");
        Console.WriteLine("Commands: init, keygen, add <file>, commit, checkout <hash>, log, verify <hash>, remote <subcmd>, pull <remote>, push <remote>");
    }

    static void HandleInit()
    {
        Directory.CreateDirectory(".codeflow");
        Directory.CreateDirectory(".codeflow/objects");
        Directory.CreateDirectory(".codeflow/keys");
        Console.WriteLine("Initialized new CodeFlow repo in .codeflow/");
        var cfgPath = CodeFlow.Core.RepoConfig.ConfigPath(Directory.GetCurrentDirectory());
        if (!File.Exists(cfgPath))
        {
            new CodeFlow.Core.RepoConfig().Save(Directory.GetCurrentDirectory());
        }
    }

    static void HandleKeyGen()
    {
        KeyManager.EnsureKeysDirectory();

        if (KeyManager.KeysExist())
        {
            Console.Write("Keys already exist. Overwrite? (y/N): ");
            var resp = Console.ReadLine();
            if (!string.Equals(resp, "y", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("Aborted.");
                return;
            }
        }

        var (priv, pub) = KeyManager.GenerateAndSaveKeyPair();
        Console.WriteLine("Generated Ed25519 key pair.");
        Console.WriteLine($"Public key (base64): {Convert.ToBase64String(pub)}");
        Console.WriteLine("Private key saved to .codeflow/keys/private.key (raw bytes). Keep it safe!");
    }

    static void HandleCommit(string[] args)
    {
        var repoRoot = Directory.GetCurrentDirectory();
        var idx = new CodeFlow.Storage.Index(repoRoot);
        var stagedFiles = idx.Load();
        if (stagedFiles.Count == 0) { Console.WriteLine("Nothing to commit, working tree clean."); return; }

        var blobStore = new BlobStore(".codeflow/objects");
        var treeStore = new TreeStore(blobStore);
        var store = new ContentAddressableStore(".codeflow/objects");
        var head = store.ReadHead();

        var newTreeEntries = new Dictionary<string, Tree.TreeEntry>();

        if (!string.IsNullOrEmpty(head))
        {
            // FIX: Add null check before parsing
            var parentCommitJson = store.GetObject(head);
            if (parentCommitJson != null)
            {
                var parentCommit = Commit.FromJson(parentCommitJson);
                var parentTree = treeStore.LoadTree(parentCommit.TreeHash);
                foreach (var entry in parentTree.Entries)
                {
                    newTreeEntries[entry.Path] = entry;
                }
            }
        }

        foreach (var stagedFile in stagedFiles)
        {
            newTreeEntries[stagedFile.Key] = new Tree.TreeEntry
            {
                Path = stagedFile.Key,
                Hash = stagedFile.Value,
                Type = "blob"
            };
        }

        var finalTree = new Tree();
        finalTree.Entries.AddRange(newTreeEntries.Values.OrderBy(e => e.Path));
        var treeHash = treeStore.SaveTree(finalTree);

        if (!KeyManager.KeysExist()) { Console.WriteLine("No keys. Run keygen."); return; }
        var (privRaw, pubRaw) = KeyManager.LoadKeyPair();
        using var key = KeyManager.ImportPrivateKey(privRaw);

        var message = args.Length > 0 ? string.Join(' ', args) : "Commit";
        var commit = new CodeFlow.Core.Commit
        {
            Author = Convert.ToBase64String(pubRaw),
            Message = message,
            Timestamp = DateTime.UtcNow,
            ParentHash = head,
            Changes = stagedFiles.Keys.ToArray(),
            TreeHash = treeHash
        };
        commit.SignWithKey(key);

        var json = commit.ToJson();
        var hash = store.SaveObject(json);
        commit.Hash = hash; // This assignment is safe.
        store.UpdateHead(hash);

        idx.Clear();

        Console.WriteLine($"Committed: {hash} (tree: {treeHash})");
    }

    static void HandleLog()
    {
        var store = new ContentAddressableStore(".codeflow/objects");
        var head = store.ReadHead();
        if (string.IsNullOrEmpty(head))
        {
            Console.WriteLine("No commits yet.");
            return;
        }

        var current = head;
        while (!string.IsNullOrEmpty(current))
        {
            var raw = store.GetObject(current);
            if (raw == null)
            {
                Console.WriteLine($"Missing object: {current}");
                break;
            }

            var commit = Commit.FromJson(raw);
            var verified = commit.VerifySignature() ? "VALID" : "INVALID";
            Console.WriteLine("--------------------------------------------------");
            Console.WriteLine($"Commit: {current}");
            Console.WriteLine($"Author(pub base64): {commit.Author}");
            Console.WriteLine($"Timestamp: {commit.Timestamp:O}");
            Console.WriteLine($"Message: {commit.Message}");
            Console.WriteLine($"Verification: {verified}");
            Console.WriteLine();

            current = commit.ParentHash;
        }
    }

    static void HandleVerify(string hash)
    {
        var store = new ContentAddressableStore(".codeflow/objects");
        var raw = store.GetObject(hash);
        if (raw == null)
        {
            Console.WriteLine($"Commit {hash} not found.");
            return;
        }

        var commit = Commit.FromJson(raw);
        var ok = commit.VerifySignature();
        Console.WriteLine($"Commit {hash} signature verification: {(ok ? "VALID" : "INVALID")}");
    }

    static void HandleAdd(string[] args)
    {
        if (args.Length < 1) { Console.WriteLine("Usage: codeflow add <file>"); return; }
        var file = args[0];
        if (!File.Exists(file)) { Console.WriteLine("File not found."); return; }

        var repoRoot = Directory.GetCurrentDirectory();
        var cfg = CodeFlow.Core.RepoConfig.Load(repoRoot);

        var blobStore = new BlobStore(".codeflow/objects");
        var idx = new CodeFlow.Storage.Index(repoRoot);

        var fi = new FileInfo(file);
        if (fi.Length > cfg.LargeFileThresholdBytes)
        {
            Console.WriteLine($"File {file} is large ({fi.Length} bytes). Splitting into chunks...");

            var chunker = new CodeFlow.Storage.Chunker(blobStore);
            var pointer = chunker.SaveLargeFile(file);

            var json = pointer.ToJson();
            var hash = blobStore.SaveBlob(System.Text.Encoding.UTF8.GetBytes(json));

            idx.AddOrUpdate(file.Replace('\\', '/'), hash);
            Console.WriteLine($"Added large file {file} as pointer -> {hash} ({pointer.ChunkHashes.Count} chunks)");
        }
        else
        {
            var bytes = File.ReadAllBytes(file);
            var hash = blobStore.SaveBlob(bytes);
            idx.AddOrUpdate(file.Replace('\\', '/'), hash);
            Console.WriteLine($"Added {file} -> {hash}");
        }
    }

    static void HandleCheckout(string[] args)
    {
        var store = new ContentAddressableStore(".codeflow/objects");
        string? targetCommitHash;

        if (args.Length == 0)
        {
            targetCommitHash = store.ReadHead();
            if (string.IsNullOrEmpty(targetCommitHash))
            {
                Console.WriteLine("No commit specified and repository has no history (HEAD is empty).");
                return;
            }
            Console.WriteLine($"Checking out current HEAD ({targetCommitHash.Substring(0, 12)})...");
        }
        else
        {
            targetCommitHash = args[0];
            Console.WriteLine($"Checking out commit {targetCommitHash}...");
        }

        // FIX: Change variable to nullable and add a null check.
        string? rawCommit = store.GetObject(targetCommitHash);
        if (rawCommit == null) { Console.WriteLine($"Commit '{targetCommitHash}' not found."); return; }

        var commit = CodeFlow.Core.Commit.FromJson(rawCommit);
        if (string.IsNullOrEmpty(commit.TreeHash)) { Console.WriteLine("Commit has no associated tree."); return; }

        RestoreWorkspaceToTree(commit.TreeHash);

        Console.WriteLine("Checkout complete. Your working directory now matches the commit.");
    }

    private static void RestoreWorkspaceToTree(string rootTreeHash)
    {
        var repoRoot = Directory.GetCurrentDirectory();
        var blobStore = new BlobStore(".codeflow/objects");
        var treeStore = new TreeStore(blobStore);
        var rootTree = treeStore.LoadTree(rootTreeHash);

        if (rootTree == null)
        {
            Console.WriteLine("[Error] Could not load the root tree object from the repository.");
            return;
        }

        var expectedPaths = new HashSet<string>(rootTree.Entries.Select(e => e.Path.Replace('\\', '/')));

        var actualPaths = new List<string>();
        var codeflowDir = Path.GetFullPath(".codeflow").TrimEnd(Path.DirectorySeparatorChar);
        if (Directory.Exists(repoRoot))
        {
            foreach (var fullPath in Directory.EnumerateFileSystemEntries(repoRoot, "*", SearchOption.AllDirectories))
            {
                if (Path.GetFullPath(fullPath).StartsWith(codeflowDir)) continue;
                actualPaths.Add(Path.GetRelativePath(repoRoot, fullPath).Replace('\\', '/'));
            }
        }

        var pathsToDelete = actualPaths.Where(p => !expectedPaths.Contains(p)).ToList();
        foreach (var path in pathsToDelete.OrderByDescending(p => p.Length))
        {
            var fullPath = Path.Combine(repoRoot, path);
            if (File.Exists(fullPath))
            {
                File.Delete(fullPath);
                Console.WriteLine($" - Deleted file {path}");
            }
            else if (Directory.Exists(fullPath))
            {
                if (!Directory.EnumerateFileSystemEntries(fullPath).Any())
                {
                    Directory.Delete(fullPath);
                    Console.WriteLine($" - Deleted directory {path}");
                }
            }
        }

        foreach (var entry in rootTree.Entries)
        {
            var entryFullPath = Path.Combine(repoRoot, entry.Path);
            var entryDir = Path.GetDirectoryName(entryFullPath);

            if (!string.IsNullOrEmpty(entryDir) && !Directory.Exists(entryDir))
            {
                Directory.CreateDirectory(entryDir);
            }

            if (entry.Type == "blob")
            {
                var bytes = blobStore.GetBlob(entry.Hash);
                if (bytes == null) { Console.WriteLine($"[Error] Missing blob {entry.Hash} for {entry.Path}"); continue; }

                var text = Encoding.UTF8.GetString(bytes);
                if (text.Contains("ChunkHashes") && text.Contains("TotalSize"))
                {
                    var ptr = LargeFilePointer.FromJson(text);
                    var chunker = new Chunker(blobStore);
                    chunker.RestoreLargeFile(ptr, entryFullPath);
                    Console.WriteLine($" + Restored large file {entry.Path}");
                }
                else
                {
                    File.WriteAllBytes(entryFullPath, bytes);
                    Console.WriteLine($" + Restored file {entry.Path}");
                }
            }
        }
    }

    static void HandleRemote(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("Usage: codeflow remote <add|list|set-threshold>");
            Console.WriteLine("  add <name> <url> <repo> <bucket> <access-key> <secret-key>");
            Console.WriteLine("  list");
            Console.WriteLine("  set-threshold <bytes> (default 104857600 = 100MiB)");
            return;
        }

        var repoRoot = Directory.GetCurrentDirectory();
        var cfg = CodeFlow.Core.RepoConfig.Load(repoRoot);

        switch (args[0])
        {
            case "add":
                if (args.Length < 7) // Corrected argument count check
                {
                    Console.WriteLine("Usage: codeflow remote add <name> <url> <repo> <bucket> <access-key> <secret-key>");
                    return;
                }
                var rc = new CodeFlow.Core.RemoteConfig
                {
                    Name = args[1],
                    Type = "cfs",
                    Url = args[2],
                    Repo = args[3],
                    Bucket = args[4],
                    AccessKey = args[5],
                    SecretKey = args[6]
                };
                cfg.AddOrUpdate(rc);
                cfg.Save(repoRoot);
                Console.WriteLine($"Added remote '{rc.Name}' -> {rc.Type} {rc.Url} repo={rc.Repo}");
                break;

            case "list":
                if (cfg.Remotes.Count == 0)
                {
                    Console.WriteLine("No remotes configured.");
                    return;
                }
                foreach (var r in cfg.Remotes)
                {
                    var star = cfg.Default == r ? "*" : " ";
                    Console.WriteLine($"{star} {r.Name}\t{r.Type}\t{r.Url}\trepo={r.Repo}");
                }
                Console.WriteLine($"Large file threshold: {cfg.LargeFileThresholdBytes} bytes");
                break;

            case "set-threshold":
                if (args.Length < 2 || !long.TryParse(args[1], out var th))
                {
                    Console.WriteLine("Usage: codeflow remote set-threshold <bytes>");
                    return;
                }
                cfg.LargeFileThresholdBytes = th;
                cfg.Save(repoRoot);
                Console.WriteLine($"Set LargeFileThresholdBytes = {th}");
                break;

            default:
                Console.WriteLine("Unknown subcommand. Use: add | list | set-threshold");
                break;
        }
    }

    static void HandlePull(string remoteName)
    {
        var cfg = CodeFlow.Core.RepoConfig.Load(Directory.GetCurrentDirectory());
        var remote = cfg.Remotes.FirstOrDefault(r => r.Name == remoteName);
        if (remote == null) { Console.WriteLine($"Remote '{remoteName}' not found."); return; }

        var localStore = new ContentAddressableStore(".codeflow/objects");
        var remoteProvider = new MinioStorageProvider(remote.Url, remote.Bucket, remote.AccessKey, remote.SecretKey);

        byte[]? remoteHeadBytes;
        try
        {
            remoteHeadBytes = remoteProvider.DownloadObjectAsync(".codeflow/HEAD").GetAwaiter().GetResult();
        }
        catch (MinioException ex)
        {
            Console.WriteLine($"Error fetching remote HEAD: {ex.Message}");
            return;
        }

        if (remoteHeadBytes == null || remoteHeadBytes.Length == 0)
        {
            Console.WriteLine("Remote repository is empty or has no HEAD.");
            return;
        }

        var remoteHeadHash = Encoding.UTF8.GetString(remoteHeadBytes);
        Console.WriteLine($"Pulling changes from remote '{remoteName}'...");

        var q = new Queue<string>();
        var seen = new HashSet<string>();
        q.Enqueue(remoteHeadHash);

        while (q.Any())
        {
            var hash = q.Dequeue();
            if (!seen.Add(hash)) continue;

            // FIX: Change variable to nullable and add a null check.
            string? localJson = localStore.GetObject(hash);
            if (localJson != null)
            {
                // Already have it locally, but still enqueue children
                EnqueueChildren(localJson, q);
                continue;
            }

            // Fetch from remote
            Console.WriteLine($"Fetching object {hash.Substring(0, 12)}...");
            byte[]? remoteBytes;
            try
            {
                remoteBytes = remoteProvider.DownloadObjectAsync(hash).GetAwaiter().GetResult();
            }
            catch (MinioException ex)
            {
                Console.WriteLine($"Error fetching object {hash}: {ex.Message}");
                return;
            }

            if (remoteBytes == null)
            {
                Console.WriteLine($"Error: Object {hash} not found on remote.");
                return;
            }

            localStore.SaveObject(remoteBytes, hash);

            // If it's text (commit/tree/pointer), parse and enqueue children
            if (!IsBinaryData(remoteBytes))
            {
                try
                {
                    var text = Encoding.UTF8.GetString(remoteBytes);
                    EnqueueChildren(text, q);
                }
                catch
                {
                    // Binary blob: no children to process
                }
            }
        }

        localStore.UpdateHead(remoteHeadHash);
        Console.WriteLine($"Pull successful. Updated HEAD to {remoteHeadHash}");
    }
}

