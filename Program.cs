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
        switch (mode)
        {
          case "-e":
            AnsiConsole.WriteLine("Beginning Encryption...");
            await encryptionUtil.EncryptAsync(filepath, password);
            break;
          case "-d":
            AnsiConsole.WriteLine("Beginning Decryption...");
            await encryptionUtil.DecryptAsync(filepath, password);
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
  }
}
