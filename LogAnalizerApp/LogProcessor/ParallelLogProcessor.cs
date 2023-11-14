using System.Text;
using System.Diagnostics;
using LogAnalizerApp.Enums;
using System.Collections.Concurrent;
using LogAnalizerApp.LogProcessor.Base;

namespace LogAnalizerApp.LogProcessor
{
    /// <summary>
    /// Processes log files in parallel to count IP hits and resolves IP addresses to hostnames.
    /// </summary>
    internal class ParallelLogProcessor : ILogProcessor
    {
        private bool _isRunning = false;

        private readonly int _chunkSize;
        private readonly DNSResolver _dnsResolver = new();
        private readonly ConcurrentDictionary<string, int> _ipHitCounts = new();
        private readonly ConcurrentDictionary<string, string> _ipResolvedAddress = new();

        /// <summary>
        /// Initializes a new instance of the ParallelLogProcessor with a specified chunk size for processing.
        /// </summary>
        /// <param name="chunkSize">The chunk size to use when reading the log file.</param>
        public ParallelLogProcessor(ChunkSize chunkSize = ChunkSize.XLarge)
        {
            _chunkSize = (int)chunkSize;
        }

        /// <summary>
        /// Asynchronously analyzes the log file and counts IP address hits.
        /// </summary>
        /// <param name="filePath">The path to the log file to be analyzed.</param>
        public async Task AnalyzeLogFileAsync(string filePath)
        {
            if (_isRunning)
            {
                Console.WriteLine("Log file processing is already in progress.");
                return;
            }

            _isRunning = true;

            if (!File.Exists(filePath))
            {
                Console.WriteLine("Invalid file path.");
                return;
            }

            _ipHitCounts.Clear();
            var stopwatch = Stopwatch.StartNew();

            var blocks = await SplitIntoBlocksAsync(filePath);
            await ProcessBlocksAsync(blocks);

            stopwatch.Stop();
            Console.WriteLine($"\nProcessing completed  in {stopwatch.Elapsed}");

            _isRunning = false;
        }

        /// <summary>
        /// Displays the IP hit counts and resolved hostnames.
        /// If an IP address has not been resolved in the moment of call,
        /// it will display as 'Unresolved ip address'.
        /// </summary>
        public void DisplayIPAnalysisResults()
        {
            Console.WriteLine("\n===IP Analysis result===");
            var result = _ipHitCounts.OrderByDescending(x => x.Value);

            // Print result
            foreach (var item in result)
            {
                _ipResolvedAddress.TryGetValue(item.Key, out string hostname);
                hostname = hostname ?? "Unresolved ip address";

                Console.WriteLine($"<{hostname}>({item.Key}) - {_ipHitCounts[item.Key]}");
            }
        }

        /// <summary>
        /// Splits the log file into blocks, with each block containing lines from one '#Fields' declaration to the next.
        /// </summary>
        /// <param name="filePath">The path to the log file.</param>
        /// <returns>A list of log file blocks, each as a string.</returns>
        private async Task<List<string>> SplitIntoBlocksAsync(string filePath)
        {
            var blocks = new List<string>();
            var currentBlock = new StringBuilder();

            using (var reader = new StreamReader(filePath))
            {
                string line;
                bool isNewBlock = false;

                while ((line = await reader.ReadLineAsync()) != null)
                {
                    if (line.StartsWith("#Fields"))
                    {
                        if (isNewBlock)
                        {
                            blocks.Add(currentBlock.ToString());
                            currentBlock.Clear();
                        }
                        isNewBlock = true;
                    }
                    if (isNewBlock)
                    {
                        currentBlock.AppendLine(line);
                    }
                }

                if (currentBlock.Length > 0)
                {
                    blocks.Add(currentBlock.ToString());
                }
            }

            return blocks;
        }

        /// <summary>
        /// Processes each block of log entries in parallel. Each block is expected to start with a '#Fields' line followed by log entries.
        /// </summary>
        /// <param name="blocks">The collection of log file blocks to process.</param>
        /// <returns>A Task representing the asynchronous operation of processing all blocks.</returns>
        private async Task ProcessBlocksAsync(IEnumerable<string> blocks)
        {
            var processingTasks = new List<Task>();

            foreach (var block in blocks)
            {
                processingTasks.Add(Task.Run(() => ProcessBlock(block)));
            }

            await Task.WhenAll(processingTasks);
        }

        /// <summary>
        /// Processes a single block of log entries. The method partitions the block into chunks and processes each chunk in parallel.
        /// </summary>
        /// <param name="block">A string representing the block of log entries to process.</param>
        private void ProcessBlock(string block)
        {
            var lines = block.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.RemoveEmptyEntries);

            // Assume the first line is the #Fields line
            var ipAddressPosition = Array.IndexOf(lines[0].Split(' '), "c-ip") - 1;

            // Partition the lines into chunks based on the desired chunk size
            var chunks = PartitionIntoChunks(lines.Skip(1), _chunkSize); // Skip the #Fields line

            // Define parallel options
            var parallelOptions = new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount };

            // Process each chunk in parallel
            Parallel.ForEach(chunks, parallelOptions, chunk =>
            {
                ProcessChunk(chunk.ToArray(), ipAddressPosition);
            });
        }

        /// <summary>
        /// Partitions a sequence of log entries into chunks of approximately equal size in bytes.
        /// </summary>
        /// <param name="lines">The sequence of log entries to partition.</param>
        /// <param name="chunkSizeInBytes">The target size for each chunk, in bytes.</param>
        /// <returns>An enumerable of string enumerables, where each inner enumerable represents a chunk of log entries.</returns>
        private IEnumerable<IEnumerable<string>> PartitionIntoChunks(IEnumerable<string> lines, int chunkSizeInBytes)
        {
            int currentChunkSize = 0;
            var currentChunk = new List<string>();

            foreach (var line in lines)
            {
                int lineSize = Encoding.UTF8.GetByteCount(line + Environment.NewLine);

                if (currentChunkSize + lineSize > chunkSizeInBytes && currentChunk.Any())
                {
                    // Current chunk is full, yield return and start a new chunk
                    yield return currentChunk;
                    currentChunk = new List<string>();
                    currentChunkSize = 0;
                }

                // Add the line to the current chunk and update the size
                currentChunk.Add(line);
                currentChunkSize += lineSize;
            }

            // Yield the last chunk if it has any lines
            if (currentChunk.Any())
            {
                yield return currentChunk;
            }
        }

        /// <summary>
        /// Processes a chunk of log entries, updating the count of IP address hits.
        /// </summary>
        /// <param name="chunk">An array of log entry strings that constitute a chunk.</param>
        /// <param name="ipAddressPosition">The position of the IP address within a log entry.</param>
        private void ProcessChunk(string[] chunk, int ipAddressPosition)
        {
            foreach (var line in chunk)
            {
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#")) continue;

                var entries = line.Split(' ');
                if (entries.Length > ipAddressPosition)
                {
                    string ip = entries[ipAddressPosition];
                    _ipHitCounts.AddOrUpdate(ip, 1, (key, oldValue) => oldValue + 1);

                    // If the IP was not in the dictionary, we start a new task to resolve it.
                    if (_ipResolvedAddress.TryAdd(ip, null))
                    {
                        Task.Run(() => ResolveIPAsync(ip));
                    }
                }
            }
        }

        /// <summary>
        /// Resolves an IP address to its corresponding hostname asynchronously and updates the resolved addresses dictionary.
        /// </summary>
        /// <param name="ip">The IP address to resolve.</param>
        private async Task ResolveIPAsync(string ip)
        {
            // Perform the DNS resolution and update the _resolvedIPs dictionary.
            var hostname = await _dnsResolver.ResolveIPToHostnameAsync(ip);
            
            _ipResolvedAddress[ip] = hostname;
        }
    }
}