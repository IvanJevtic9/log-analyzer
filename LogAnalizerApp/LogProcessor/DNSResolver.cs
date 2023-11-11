using System.Net;

namespace LogAnalizerApp.LogProcessor
{
    /// <summary>
    /// Provides DNS resolution services.
    /// </summary>
    internal class DNSResolver
    {
        /// <summary>
        /// Resolves an IP address to a hostname asynchronously.
        /// </summary>
        /// <param name="ipAddress">The IP address to resolve.</param>
        /// <returns>The hostname if resolution is successful, otherwise "Unknown host".</returns>
        public async Task<string> ResolveIPToHostnameAsync(string ipAddress)
        {
            try
            {
                var hostEntry = await Dns.GetHostEntryAsync(ipAddress);
                return hostEntry.HostName;
            }
            catch (Exception)
            {
                return "Unknown host";
            }
        }
    }
}
