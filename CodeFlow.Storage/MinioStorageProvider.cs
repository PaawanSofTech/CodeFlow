using System;
using System.IO;
using System.Threading.Tasks;
using Minio;
using Minio.DataModel.Args;
using Minio.Exceptions;
using System.Collections.Generic;

namespace CodeFlow.Storage
{
    public class MinioStorageProvider
    {
        private readonly IMinioClient _client;
        private readonly string _bucket;

        // ✅ Fixed method
        public async Task<HashSet<string>> ListAllObjectKeysAsync()
        {
            var keys = new HashSet<string>();
            try
            {
                var listArgs = new ListObjectsArgs()
                    .WithBucket(_bucket)
                    .WithRecursive(true);

                // ✅ Correct method in MinIO .NET v6+
                var items = _client.ListObjectsEnumAsync(listArgs);

                await foreach (var item in items)
                {
                    if (!string.IsNullOrEmpty(item.Key))
                        keys.Add(item.Key);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Error] Could not list objects from bucket '{_bucket}': {ex.Message}");
            }
            return keys;
        }


        public MinioStorageProvider(string fullEndpointUrl, string bucket, string accessKey, string secretKey)
        {
            if (string.IsNullOrWhiteSpace(fullEndpointUrl))
                throw new ArgumentException("Endpoint URL cannot be empty", nameof(fullEndpointUrl));

            var uri = new Uri(fullEndpointUrl);
            var endpoint = uri.Authority;
            var isSecure = uri.Scheme == Uri.UriSchemeHttps;

            var clientBuilder = new MinioClient()
                .WithEndpoint(endpoint)
                .WithCredentials(accessKey, secretKey);

            if (isSecure)
            {
                clientBuilder.WithSSL();
            }

            _client = clientBuilder.Build();
            _bucket = bucket ?? throw new ArgumentNullException(nameof(bucket));

            EnsureBucketExistsAsync().Wait();
        }

        private async Task EnsureBucketExistsAsync()
        {
            var bucketExistsArgs = new BucketExistsArgs().WithBucket(_bucket);
            bool found = await _client.BucketExistsAsync(bucketExistsArgs);
            if (!found)
            {
                var makeBucketArgs = new MakeBucketArgs().WithBucket(_bucket);
                await _client.MakeBucketAsync(makeBucketArgs);
            }
        }

        public async Task UploadObjectAsync(string objectName, Stream data)
        {
            if (string.IsNullOrWhiteSpace(objectName))
                throw new ArgumentException("Object name cannot be empty", nameof(objectName));
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            if (data.CanSeek)
            {
                data.Position = 0;
            }

            var putObjectArgs = new PutObjectArgs()
                .WithBucket(_bucket)
                .WithObject(objectName)
                .WithStreamData(data)
                .WithObjectSize(data.Length)
                .WithContentType("application/octet-stream");

            await _client.PutObjectAsync(putObjectArgs);
        }

        public async Task<byte[]?> DownloadObjectAsync(string objectName) // ✅ make return nullable
        {
            try
            {
                using var stream = new MemoryStream();
                var getObjectArgs = new GetObjectArgs()
                    .WithBucket(_bucket)
                    .WithObject(objectName)
                    .WithCallbackStream((s) =>
                    {
                        s.CopyTo(stream);
                    });

                await _client.GetObjectAsync(getObjectArgs).ConfigureAwait(false);
                return stream.ToArray();
            }
            catch (ObjectNotFoundException)
            {
                return null; // ✅ fixes CS8603 (nullable return)
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error downloading object {objectName}: {ex.Message}");
                throw;
            }
        }
    }
}
