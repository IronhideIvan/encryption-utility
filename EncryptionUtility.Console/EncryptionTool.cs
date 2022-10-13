using System;
using EncryptionUtility.Crypto;
using Spectre.Console;

namespace EncryptionUtility.Console
{
  public class EncryptionTool
  {
    private const int FILE_BUFFER = 1048576;
    private const int RAW_STRING_BUFFER = 512;

    public async Task ProcessAsync(ArgumentConfig config)
    {
      var encryptor = new AesEncryption(
              new AesEncryptionConfiguration
              {
                BufferBytes = FILE_BUFFER
              }
            );

      long totalBytes = -1;
      byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(config.Password);
      var consoleStatus = AnsiConsole.Status()
        .Spinner(Spinner.Known.Star);

      if (config.InputType == InputType.File)
      {
        string filepath = config.Input;
        totalBytes = new FileInfo(filepath).Length;
        if (totalBytes < FILE_BUFFER)
        {
          encryptor = new AesEncryption(
            new AesEncryptionConfiguration
            {
              BufferBytes = (int)totalBytes
            }
          );
        }

        if (config.ProcessingType == ProcessingType.Encrypt)
        {
          string encryptedFilepath = filepath + ".encrypted";
          if (config.Verbosity == Verbosity.Silent)
          {
            await encryptor.EncryptFileAsync(
              filepath,
              encryptedFilepath,
              passwordBytes);
          }
          else
          {
            await consoleStatus.StartAsync(GetProgressMessage(0, 0), async ctx =>
            {
              await encryptor.EncryptFileAsync(
                filepath,
                encryptedFilepath,
                passwordBytes,
                config.Verbosity == Verbosity.Silent
                ? null
                : (long progress) =>
                  {
                    ctx.Status(GetProgressMessage(progress, totalBytes));
                    return Task.CompletedTask;
                  });
            });
          }

          AnsiConsole.Write(Path.GetFullPath(encryptedFilepath));
        }
        else
        {
          string decryptedFilepath = filepath + ".decrypted";
          if (config.Verbosity == Verbosity.Silent)
          {
            await encryptor.DecryptFileAsync(
              filepath,
              decryptedFilepath,
              passwordBytes);
          }
          else
          {
            await consoleStatus.StartAsync(GetProgressMessage(0, 0), async ctx =>
            {
              await encryptor.DecryptFileAsync(
                filepath,
                decryptedFilepath,
                passwordBytes,
                config.Verbosity == Verbosity.Silent
                ? null
                : (long progress) =>
                  {
                    ctx.Status(GetProgressMessage(progress, totalBytes));
                    return Task.CompletedTask;
                  });
            });

            AnsiConsole.Write(Path.GetFullPath(decryptedFilepath));
          }
        }
      }
      else if (config.InputType == InputType.RawString)
      {
        encryptor = new AesEncryption(
          new AesEncryptionConfiguration
          {
            BufferBytes = RAW_STRING_BUFFER
          }
        );

        byte[]? output = null;

        if (config.ProcessingType == ProcessingType.Encrypt)
        {
          byte[] inputBytes = System.Text.Encoding.UTF8.GetBytes(config.Input);
          totalBytes = inputBytes.Length;
          if (config.Verbosity == Verbosity.Silent)
          {
            output = await encryptor.EncryptAsync(
              inputBytes,
              passwordBytes);
          }
          else
          {
            await consoleStatus.StartAsync(GetProgressMessage(0, 0), async ctx =>
            {
              output = await encryptor.EncryptAsync(
                inputBytes,
                passwordBytes,
                config.Verbosity == Verbosity.Silent
                ? null
                : (long progress) =>
                  {
                    ctx.Status(GetProgressMessage(progress, totalBytes));
                    return Task.CompletedTask;
                  });
            });
          }

          if (output == null)
          {
            throw new Exception("Unknown Error: encryption created no output.");
          }

          AnsiConsole.Write(Convert.ToBase64String(output, Base64FormattingOptions.None));
        }
        else
        {
          byte[] inputBytes = Convert.FromBase64String(config.Input);
          totalBytes = inputBytes.Length;
          if (config.Verbosity == Verbosity.Silent)
          {
            output = await encryptor.DecryptAsync(
              inputBytes,
              passwordBytes);
          }
          else
          {
            await consoleStatus.StartAsync(GetProgressMessage(0, 0), async ctx =>
            {
              output = await encryptor.DecryptAsync(
                inputBytes,
                passwordBytes,
                config.Verbosity == Verbosity.Silent
                ? null
                : (long progress) =>
                  {
                    ctx.Status(GetProgressMessage(progress, totalBytes));
                    return Task.CompletedTask;
                  });
            });
          }

          if (output == null)
          {
            throw new Exception("Unknown Error: encryption created no output.");
          }

          AnsiConsole.Write(System.Text.Encoding.UTF8.GetString(output));
        }
      }
      else
      {
        throw new NotImplementedException(config.InputType.ToString());
      }
    }

    private string GetProgressMessage(long progress, long total)
    {
      return $"Progress: {GetPercentage(progress, total)} - {progress}/{total} bytes";
    }

    private string GetPercentage(long numerator, long denominator)
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
