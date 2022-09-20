using System;
using System.IO;
using System.Threading.Tasks;
using Spectre.Console;

namespace EncryptionUtility
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            try
            {
                if (args == null || args.Length != 3)
                {
                    AnsiConsole.WriteLine("Invalid number of arguments. There should be three arguments with the following format:");
                    AnsiConsole.WriteLine("");
                    AnsiConsole.WriteLine("\t[-e|-d] <password> <filepath>");
                    AnsiConsole.WriteLine("");
                    return;
                }

                var mode = args[0];
                var password = args[1];
                var filepath = args[2];

                if (!File.Exists(filepath))
                {
                    AnsiConsole.WriteLine($"Given filepath does not exist: '{filepath}'");
                    return;
                }

                var encryptionUtil = new AesEncryption();

                var consoleStatus = AnsiConsole.Status()
                  .Spinner(Spinner.Known.Star);

                var totalFileBytes = new FileInfo(filepath).Length;

                switch (mode)
                {
                    case "-e":
                        AnsiConsole.WriteLine("Beginning Encryption...");
                        await consoleStatus.StartAsync(GetProgressMessage(0, 0), async ctx =>
                        {
                            await encryptionUtil.EncryptFileAsync(
                                filepath,
                                filepath + ".aes",
                                System.Text.Encoding.UTF8.GetBytes(password), (long progress) =>
                            {
                                ctx.Status(GetProgressMessage(progress, totalFileBytes));
                                return Task.CompletedTask;
                            });
                        });
                        break;
                    case "-d":
                        AnsiConsole.WriteLine("Beginning Decryption...");
                        await consoleStatus.StartAsync(GetProgressMessage(0, 0), async ctx =>
                        {
                            await encryptionUtil.DecryptFileAsync(
                                filepath,
                                filepath + ".decrypted",
                                System.Text.Encoding.UTF8.GetBytes(password), (long progress) =>
                            {
                                ctx.Status(GetProgressMessage(progress, totalFileBytes));
                                return Task.CompletedTask;
                            });
                        });
                        break;
                    default:
                        AnsiConsole.WriteLine($"Unknown mode given. Options are '-e' to encrypt and '-d' to decrypt. Given: '{mode}'");
                        return;
                }
            }
            catch (Exception ex)
            {
                AnsiConsole.WriteException(ex);
            }
        }

        private static string GetProgressMessage(long progress, long total)
        {
            return $"Progress: {GetPercentage(progress, total)} - {progress}/{total} bytes";
        }

        private static string GetPercentage(long numerator, long denominator)
        {
            if (denominator == 0)
            {
                return "ERROR";
            }

            var dNum = Convert.ToDouble(numerator);
            var dDen = Convert.ToDouble(denominator);

            var perc = Math.Round((dNum / dDen) * 100, 2);

            return string.Format("{0:N2}%", perc);
        }
    }
}
