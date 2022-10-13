using System;
using System.IO;
using System.Threading.Tasks;
using EncryptionUtility.Console;
using EncryptionUtility.Crypto;
using Spectre.Console;

namespace EncryptionUtility.Console
{
  public class Program
  {
    public static async Task Main(string[] args)
    {
      var config = new ArgumentConfig();
      try
      {
        if (args == null || args.Length == 0 || args.Any(a => a == "-h"))
        {
          WriteHelp();
          return;
        }

        for (int i = 0; i < args.Length; ++i)
        {
          var arg = args[i];
          switch (arg)
          {
            case "-verbose":
            case "-v":
              config.Verbosity = Verbosity.Verbose;
              break;
            case "-file":
            case "-f":
              config.InputType = InputType.File;
              break;
            case "-string":
            case "-s":
              config.InputType = InputType.RawString;
              break;
            case "-i":
            case "-input":
              {
                ++i;
                if (i >= args.Length)
                {
                  throw new Exception("No input provided after '-input/-i' argument.");
                }
                config.Input = args[i];
              }
              break;
            case "-password":
            case "-p":
              {
                ++i;
                if (i >= args.Length)
                {
                  throw new Exception("No input provided after '-input/-i' argument.");
                }
                config.Password = args[i];
              }
              break;
            case "-encrypt":
            case "-e":
              config.ProcessingType = ProcessingType.Encrypt;
              break;
            case "-decrypt":
            case "-d":
              config.ProcessingType = ProcessingType.Decrypt;
              break;
            default:
              throw new Exception($"Unknown argument at index {i}: {arg}");
          }
        }

        if (config.ProcessingType == ProcessingType.Unknown)
        {
          AnsiConsole.WriteLine("No processing type set");
          WriteHelp();
          throw new Exception("No processing type set.");
        }

        if (string.IsNullOrEmpty(config.Input))
        {
          AnsiConsole.WriteLine("No input provided.");
          WriteHelp();
          throw new Exception("No input provided.");
        }

        if (string.IsNullOrEmpty(config.Password))
        {
          AnsiConsole.WriteLine("No password provided.");
          WriteHelp();
          throw new Exception("No password provided.");
        }

        var encryptionTool = new EncryptionTool();
        await encryptionTool.ProcessAsync(config);
      }
      catch (Exception ex)
      {
        if (config.Verbosity != Verbosity.Silent)
        {
          AnsiConsole.WriteException(ex);
        }
        throw;
      }
    }

    private static void WriteHelp()
    {
      AnsiConsole.WriteLine("The following are commands and general information about the tool:");
      AnsiConsole.WriteLine("Commands");
      AnsiConsole.WriteLine("-v/-verbose\tVerbose Output");
      AnsiConsole.WriteLine("-f/-file\tFile Input Type");
      AnsiConsole.WriteLine("-s/-string\tString Input Type (DEFAULT)");
      AnsiConsole.WriteLine("-i/-input\tInput Flag (ex. -i <input>)");
      AnsiConsole.WriteLine("-p/-password\tpassword Flag (ex. -p <password>)");
      AnsiConsole.WriteLine("-e/-encrpyt\tEncrypt Input Contents");
      AnsiConsole.WriteLine("-d/-decrypt\tDecrypt Input Contents");
      AnsiConsole.WriteLine("Examples:");
      AnsiConsole.WriteLine("-v -f -e -i <filepath> -p <password>");
      AnsiConsole.WriteLine("-e -i \"Encrypt ME!\" -p <password>");
      AnsiConsole.WriteLine("");
    }
  }
}
