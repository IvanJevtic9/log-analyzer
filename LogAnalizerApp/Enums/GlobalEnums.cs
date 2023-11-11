namespace LogAnalizerApp.Enums
{
    /// <summary>
    /// Defines various sizes for data chunks to be used in log file processing.
    /// </summary>
    public enum ChunkSize
    {
        Small = 4 * 1024,      // 4 KB
        Medium = 64 * 1024,    // 64 KB
        Large = 512 * 1024,    // 512 KB
        XLarge = 1024 * 1024,  // 1 MB
        XXLarge = 4 * 1024 * 1024  // 4 MB
    }
}
