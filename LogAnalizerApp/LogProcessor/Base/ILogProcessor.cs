namespace LogAnalizerApp.LogProcessor.Base
{
    /// <summary>
    /// Defines the contract for log file processing.
    /// </summary>
    public interface ILogProcessor
    {
        /// <summary>
        /// Asynchronously analyzes the log file at the specified file path.
        /// </summary>
        /// <param name="filePath">The path to the log file to analyze.</param>
        Task AnalyzeLogFileAsync(string filePath);

        /// <summary>
        /// Displays the results of the IP address analysis from the log file.
        /// </summary>
        void DisplayIPAnalysisResults();
    }
}
