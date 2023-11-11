using LogAnalizerApp.LogProcessor;

namespace LogAnalizerApp
{
    public class Program
    {
        private static readonly string _logfilePath =
            Path.Combine(Environment.CurrentDirectory, "Logs", "ex120326.log");
        private static readonly string _logfilePath2 =
            Path.Combine(Environment.CurrentDirectory, "Logs", "ex040730.log");

        public static async Task Main(string[] args)
        {
            var logProcessor = new ParallelLogProcessor();

            // Example 1
            // IP hits are removed every time we start analyzing while dns collection no.
            await logProcessor.AnalyzeLogFileAsync(_logfilePath);

            logProcessor.DisplayIPAnalysisResults();

            Thread.Sleep(5000);

            logProcessor.DisplayIPAnalysisResults();

            // Running again
            await logProcessor.AnalyzeLogFileAsync(_logfilePath);
            logProcessor.DisplayIPAnalysisResults();

            // Example 2
            await logProcessor.AnalyzeLogFileAsync(_logfilePath2);

            logProcessor.DisplayIPAnalysisResults();

            Thread.Sleep(5000);
            logProcessor.DisplayIPAnalysisResults();

            Thread.Sleep(20000);
            logProcessor.DisplayIPAnalysisResults();
        }
    }
}