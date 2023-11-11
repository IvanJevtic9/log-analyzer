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

            if (!File.Exists(filePath))
            {
                Console.WriteLine("Invalid file path.");
                return;
            }

            _ipHitCounts.Clear();
            var stopwatch = Stopwatch.StartNew();

            await ProcessLogEntries(filePath);

            stopwatch.Stop();
            Console.WriteLine($"Processing completed  in {stopwatch.Elapsed}\n");

            _isRunning = false;
        }

        /// <summary>
        /// Processes log entries, counting IP hits and queuing IPs for DNS resolution.
        /// </summary>
        /// <param name="filePath">The path to the log file.</param>
        private async Task ProcessLogEntries(string filePath)
        {
            var tasks = new List<Task>();
            var fileLength = new FileInfo(filePath).Length;

            using (var stream = File.OpenRead(filePath))
            {
                long position = 0;

                while (position < fileLength)
                {
                    // Calculate the size of the chunk to read
                    var nextChunkSize = Math.Min(_chunkSize, fileLength - position);

                    // Read the chunk asynchronously
                    byte[] buffer = new byte[nextChunkSize];
                    stream.Seek(position, SeekOrigin.Begin);
                    int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);

                    // Find the last new line in the buffer
                    int lastNewLine = Array.LastIndexOf(buffer, (byte)'\n', bytesRead - 1);
                    if (lastNewLine == -1)
                    {
                        // if not found , it means that the chunk size was perfect.
                        lastNewLine = bytesRead;
                    }
                    else
                    {
                        // Include the newline character in the current chunk
                        lastNewLine++;
                    }

                    // Process the chunk asynchronously up to the last complete line
                    byte[] completeBuffer = new byte[lastNewLine];
                    Array.Copy(buffer, completeBuffer, lastNewLine);

                    tasks.Add(Task.Run(() => ProcessChunkAsync(completeBuffer)));

                    // Move to the next chunk, adjusting for the line boundary
                    position += lastNewLine;
                }
            }

            // Wait for all processing task to complete
            await Task.WhenAll(tasks);
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
        /// Processes a chunk of the log file asynchronously to count IP hits.
        /// </summary>
        /// <param name="buffer">The byte array containing a chunk of the log file.</param>
        private void ProcessChunkAsync(byte[] buffer)
        {
            // Convert the byte array to a string, then split into lines
            var text = Encoding.UTF8.GetString(buffer);
            var lines = text.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);

            // Process each line 
            foreach (var line in lines)
            {
                if (!string.IsNullOrWhiteSpace(line) && !line.StartsWith("#"))
                {
                    string ip = line.Split(' ')[2];
                    _ipHitCounts.AddOrUpdate(ip, 1, (key, oldValue) => oldValue + 1);

                    // If the IP was not in the dictionary, we start a new task to resolve it. 
                    if (_ipResolvedAddress.TryAdd(ip, null))
                    {
                        // We don't wait for it because it can take significantly more time than counting hits.
                        Task.Run(() => ResolveIP(ip));
                    }
                }
            }
        }

        /// <summary>
        /// Resolves an IP address to its corresponding hostname asynchronously and updates the resolved addresses dictionary.
        /// </summary>
        /// <param name="ip">The IP address to resolve.</param>
        private async Task ResolveIP(string ip)
        {
            // Perform the DNS resolution and update the _resolvedIPs dictionary.
            var hostname = await _dnsResolver.ResolveIPToHostnameAsync(ip);
            
            _ipResolvedAddress[ip] = hostname;
        }
    }
}