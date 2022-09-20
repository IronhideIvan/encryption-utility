﻿using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Spectre.Console;

namespace EncryptionUtility
{
    public class AesEncryption
    {
        public async Task EncryptAsync(string inputFile, string password)
        {
            //http://stackoverflow.com/questions/27645527/aes-encryption-on-large-files

            //generate random salt
            byte[] salt = GenerateRandomSalt();

            //create output file name
            FileStream fsCrypt = new FileStream(inputFile + ".aes", FileMode.Create);

            //convert password string to byte arrray
            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);

            //Set Rijndael symmetric encryption algorithm
            RijndaelManaged AES = new RijndaelManaged();
            AES.KeySize = 256;
            AES.BlockSize = 128;
            AES.Padding = PaddingMode.PKCS7;

            //http://stackoverflow.com/questions/2659214/why-do-i-need-to-use-the-rfc2898derivebytes-class-in-net-instead-of-directly
            //"What it does is repeatedly hash the user password along with the salt." High iteration counts.
            var key = new Rfc2898DeriveBytes(passwordBytes, salt, 50000);
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);

            //Cipher modes: http://security.stackexchange.com/questions/52665/which-is-the-best-cipher-mode-and-padding-mode-for-aes-encryption
            AES.Mode = CipherMode.CFB;

            //write salt to the begining of the output file, so in this case can be random every time
            fsCrypt.Write(salt, 0, salt.Length);

            CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateEncryptor(), CryptoStreamMode.Write);

            FileStream fsIn = new FileStream(inputFile, FileMode.Open);

            //create a buffer (1mb) so only this amount will allocate in the memory and not the whole file
            byte[] buffer = new byte[1048576];
            int read;

            try
            {
                var length = fsIn.Length;
                long currentProgress = 0;

                await AnsiConsole.Status()
                  .Spinner(Spinner.Known.Star)
                  .StartAsync($"Progress: {GetPercentage(currentProgress, length)} - {currentProgress}/{length} bytes", async ctx =>
                  {
                      while ((read = fsIn.Read(buffer, 0, buffer.Length)) > 0)
                      {
                          await cs.WriteAsync(buffer, 0, read);

                          currentProgress += buffer.Length;
                          ctx.Status($"Progress: {GetPercentage(currentProgress, length)} - {currentProgress}/{length} bytes");
                      }
                  });
                //close up
                fsIn.Close();

            }
            catch (Exception ex)
            {
                AnsiConsole.WriteException(ex);
            }
            finally
            {
                cs.Close();
                fsCrypt.Close();
            }
        }

        public async Task DecryptAsync(string inputFile, string password)
        {
            //todo:
            // - create error message on wrong password
            // - on cancel: close and delete file
            // - on wrong password: close and delete file!
            // - create a better filen name
            // - could be check md5 hash on the files but it make this slow

            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
            byte[] salt = new byte[32];

            FileStream fsCrypt = new FileStream(inputFile, FileMode.Open);
            fsCrypt.Read(salt, 0, salt.Length);

            RijndaelManaged AES = new RijndaelManaged();
            AES.KeySize = 256;
            AES.BlockSize = 128;
            var key = new Rfc2898DeriveBytes(passwordBytes, salt, 50000);
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);
            AES.Padding = PaddingMode.PKCS7;
            AES.Mode = CipherMode.CFB;

            CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateDecryptor(), CryptoStreamMode.Read);

            FileStream fsOut = new FileStream(inputFile + ".decrypted", FileMode.Create);

            int read;
            byte[] buffer = new byte[1048576];

            try
            {
                var length = new FileInfo(inputFile).Length;
                long currentProgress = 0;

                await AnsiConsole.Status()
                  .Spinner(Spinner.Known.Star)
                  .StartAsync($"Progress: {GetPercentage(currentProgress, length)} - {currentProgress}/{length} bytes", async ctx =>
                  {
                      while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
                      {
                          await fsOut.WriteAsync(buffer, 0, read);

                          currentProgress += buffer.Length;
                          ctx.Status($"Progress: {GetPercentage(currentProgress, length)} - {currentProgress}/{length} bytes");
                      }
                  });
            }
            catch (Exception ex)
            {
                AnsiConsole.WriteException(ex);
            }

            try
            {
                cs.Close();
            }
            catch (Exception ex)
            {
                AnsiConsole.WriteException(ex);
            }
            finally
            {
                fsOut.Close();
                fsCrypt.Close();
            }
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
