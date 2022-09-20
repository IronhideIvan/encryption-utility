namespace EncryptionUtility.Crypto
{
  public interface IEncryption
  {
    public delegate Task CryptoProgressAsync(long bytesProcessed);

    Task EncryptFileAsync(string inputFilepath, string outputFilepath, byte[] passwordBytes, CryptoProgressAsync? progress = null);
    Task DecryptFileAsync(string inputFile, string outputFile, byte[] passwordBytes, CryptoProgressAsync? progress = null);
    Task<byte[]> EncryptAsync(byte[] inputBytes, byte[] passwordBytes, CryptoProgressAsync? progress = null);
    Task<byte[]> DecryptAsync(byte[] inputBytes, byte[] passwordBytes, CryptoProgressAsync? progress = null);
    Task EncryptAsync(Stream inputStream, Stream outputStream, byte[] passwordBytes, CryptoProgressAsync? progress = null);
    Task DecryptAsync(Stream inputStream, Stream outputStream, byte[] passwordBytes, CryptoProgressAsync? progress = null);
  }
}
