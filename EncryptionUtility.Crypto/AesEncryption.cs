using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace EncryptionUtility.Crypto
{
  public class AesEncryption
  {
    public delegate Task CryptoProgressAsync(long bytesProcessed);

    public async Task EncryptFileAsync(string inputFilepath, string outputFilepath, byte[] password, CryptoProgressAsync? progress = null)
    {
      //create output file name
      using (FileStream fsCrypt = new FileStream(outputFilepath, FileMode.Create))
      {
        using (FileStream fsIn = new FileStream(inputFilepath, FileMode.Open))
        {
          await EncryptAsync(fsIn, fsCrypt, password, progress);
        }
      }
    }

    public async Task DecryptFileAsync(string inputFile, string outputFile, byte[] password, CryptoProgressAsync? progress = null)
    {
      using (FileStream fsCrypt = new FileStream(inputFile, FileMode.Open))
      {
        using (FileStream fsOut = new FileStream(outputFile, FileMode.Create))
        {
          await DecryptAsync(fsCrypt, fsOut, password, progress);
        }
      }
    }

    public async Task<byte[]> EncryptAsync(byte[] inputBytes, byte[] password, CryptoProgressAsync? progress = null)
    {
      using (var inputStream = new MemoryStream(inputBytes))
      {
        using (var outputStream = new MemoryStream())
        {
          await EncryptAsync(inputStream, outputStream, password, progress);
          return outputStream.ToArray();
        }
      }
    }

    public async Task<byte[]> DecryptAsync(byte[] inputBytes, byte[] password, CryptoProgressAsync? progress = null)
    {
      using (var inputStream = new MemoryStream(inputBytes))
      {
        using (var outputStream = new MemoryStream())
        {
          await DecryptAsync(inputStream, outputStream, password, progress);
          return outputStream.ToArray();
        }
      }
    }

    public async Task EncryptAsync(Stream inputStream, Stream outputStream, byte[] passwordBytes, CryptoProgressAsync? progress = null)
    {
      //http://stackoverflow.com/questions/27645527/aes-encryption-on-large-files

      //generate random salt
      byte[] salt = GenerateRandomSalt();

      //Set Rijndael symmetric encryption algorithm
      var AES = buildAesAlgorithm(passwordBytes, salt);

      //write salt to the begining of the output, so in this case can be random every time
      outputStream.Write(salt, 0, salt.Length);

      using (CryptoStream cs = new CryptoStream(outputStream, AES.CreateEncryptor(), CryptoStreamMode.Write))
      {
        //create a buffer (1mb) so only this amount will allocate in the memory and not the whole file
        byte[] buffer = new byte[1048576];
        int read;

        long currentProgress = 0;

        while ((read = inputStream.Read(buffer, 0, buffer.Length)) > 0)
        {
          await cs.WriteAsync(buffer, 0, read);

          currentProgress += buffer.Length;
          if (progress != null)
          {
            await progress.Invoke(currentProgress);
          }
        }
      }
    }

    public async Task DecryptAsync(Stream inputStream, Stream outputStream, byte[] passwordBytes, CryptoProgressAsync? progress = null)
    {
      //todo:
      // - create error message on wrong password
      // - on cancel: close and delete file
      // - on wrong password: close and delete file!
      // - create a better filen name
      // - could be check md5 hash on the files but it make this slow

      byte[] salt = new byte[32];
      inputStream.Read(salt, 0, salt.Length);

      var AES = buildAesAlgorithm(passwordBytes, salt);

      using (CryptoStream cs = new CryptoStream(inputStream, AES.CreateDecryptor(), CryptoStreamMode.Read))
      {
        int read;
        byte[] buffer = new byte[1048576];
        long currentProgress = 0;

        while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
        {
          await outputStream.WriteAsync(buffer, 0, read);

          currentProgress += buffer.Length;
          if (progress != null)
          {
            await progress.Invoke(currentProgress);
          }
        }
      }
    }

    private RijndaelManaged buildAesAlgorithm(byte[] passwordBytes, byte[] saltBytes)
    {
      //Set Rijndael symmetric encryption algorithm
      RijndaelManaged AES = new RijndaelManaged();
      AES.KeySize = 256;
      AES.BlockSize = 128;
      AES.Padding = PaddingMode.PKCS7;
      AES.Mode = CipherMode.CFB;

      //http://stackoverflow.com/questions/2659214/why-do-i-need-to-use-the-rfc2898derivebytes-class-in-net-instead-of-directly
      //"What it does is repeatedly hash the user password along with the salt." High iteration counts.
      var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 50000);
      AES.Key = key.GetBytes(AES.KeySize / 8);
      AES.IV = key.GetBytes(AES.BlockSize / 8);
      return AES;
    }

    private byte[] GenerateRandomSalt()
    {
      //Source: http://www.dotnetperls.com/rngcryptoserviceprovider
      byte[] data = new byte[32];

      using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
      {
        // Ten iterations.
        for (int i = 0; i < 10; i++)
        {
          // Fill buffer.
          rng.GetBytes(data);
        }
      }
      return data;
    }
  }
}
