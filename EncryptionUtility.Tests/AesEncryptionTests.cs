namespace EncryptionUtility.Tests;

public class AesEncryptionTests
{
  private AesEncryption _encryption;

  private const string TEST_FILE_DIRECTORY = "./tests/";
  private string _testInputFilepath = TEST_FILE_DIRECTORY + "inputfile.txt";
  private string _testOutputFilepath = TEST_FILE_DIRECTORY + "outputfile.txt";

  public AesEncryptionTests()
  {
    _encryption = new AesEncryption();
  }

  [Fact]
  public async Task AesEncryptionTests_EncryptFileAsync_FileEncryptedAsync()
  {
    var inputBytes = System.Text.Encoding.UTF8.GetBytes("TEST FILE");
    await InitializeFilesAsync(inputBytes);

    await _encryption.EncryptFileAsync(_testInputFilepath, _testOutputFilepath, inputBytes);

    var outputBytes = await File.ReadAllBytesAsync(_testOutputFilepath);

    Assert.NotNull(outputBytes);
    Assert.NotEmpty(outputBytes);
    Assert.NotEqual(GetBase64(inputBytes), GetBase64(outputBytes));
  }

  [Fact]
  public async Task AesEncryptionTests_EncryptAsync_StreamEncrypted()
  {
    var inputBytes = System.Text.Encoding.UTF8.GetBytes("TEST FILE");
    byte[] outputBytes;

    using (var inputStream = new MemoryStream(inputBytes))
    {
      using (var outputStream = new MemoryStream())
      {
        await _encryption.EncryptAsync(inputStream, outputStream, inputBytes);
        outputBytes = outputStream.ToArray();
      }
    }

    Assert.NotNull(outputBytes);
    Assert.NotEmpty(outputBytes);
    Assert.NotEqual(GetBase64(inputBytes), GetBase64(outputBytes));
  }

  [Fact]
  public async Task AesEncryptionTests_EncryptAsync_BytesEncrypted()
  {
    var inputBytes = System.Text.Encoding.UTF8.GetBytes("TEST FILE");
    var outputBytes = await _encryption.EncryptAsync(inputBytes, inputBytes);

    Assert.NotNull(outputBytes);
    Assert.NotEmpty(outputBytes);
    Assert.NotEqual(GetBase64(inputBytes), GetBase64(outputBytes));
  }

  [Theory]
  [InlineData("TEST CONTENTS. SHOULD BE THE SAME!", "123")]
  [InlineData("Nothing", "")]
  [InlineData("", "")]
  [InlineData("", ".asldhw")]
  [InlineData(".;.9z24;]-=-c-2c40c42[a", "l3p29f8;f.3")]
  public async Task AesEncryptionTests_EncryptAndDecryptAsync_ContentsUnchangedAsync(string contents, string passsword)
  {
    var inputBytes = System.Text.Encoding.UTF8.GetBytes(contents);
    var passwordBytes = System.Text.Encoding.UTF8.GetBytes(passsword);
    byte[] encryptedOutput;
    byte[] decryptedOutput;

    encryptedOutput = await _encryption.EncryptAsync(inputBytes, passwordBytes);
    decryptedOutput = await _encryption.DecryptAsync(encryptedOutput, passwordBytes);

    var decryptedString = System.Text.Encoding.UTF8.GetString(decryptedOutput);
    Assert.Equal(contents, decryptedString);
  }

  [Theory]
  [InlineData("CjM5lgRAUVdW88HvlzYEt2RliGhRmz1KqCXQ0UiAi18JufFGWkA1o9NlCPRHGONp", "123", "TEST BYTES")]
  [InlineData("yyhreYacU8Fm4PDCMNfrPAXTyDo6uFbPfHkHGzzE2j8vbkzr7827LHsfuq2OBbhM3BpWSrDw25j46sRpBhjr3FRN/aX2siPcoIK5Ss+4sD+n+ynWvV3L6vI7ENt2SyQo", ".f8c2h.20/v[]20vug23bm", "This is some other contents that should be the same")]
  public async Task AesEncryptionTests_DecryptAsync_StreamDecrypted(string encryptedContents, string encodedPassword, string expectedContents)
  {
    var encryptedBytes = Convert.FromBase64String(encryptedContents);
    var passwordBytes = System.Text.Encoding.UTF8.GetBytes(encodedPassword);
    byte[] outputBytes;

    using (var inputStream = new MemoryStream(encryptedBytes))
    {
      using (var outputStream = new MemoryStream())
      {
        await _encryption.DecryptAsync(inputStream, outputStream, passwordBytes);
        outputBytes = outputStream.ToArray();
      }
    }

    Assert.NotNull(outputBytes);
    Assert.NotEmpty(outputBytes);

    var outputContents = System.Text.Encoding.UTF8.GetString(outputBytes);
    Assert.Equal(expectedContents, outputContents);
  }

  [Theory]
  [InlineData("CjM5lgRAUVdW88HvlzYEt2RliGhRmz1KqCXQ0UiAi18JufFGWkA1o9NlCPRHGONp", "123", "TEST BYTES")]
  [InlineData("yyhreYacU8Fm4PDCMNfrPAXTyDo6uFbPfHkHGzzE2j8vbkzr7827LHsfuq2OBbhM3BpWSrDw25j46sRpBhjr3FRN/aX2siPcoIK5Ss+4sD+n+ynWvV3L6vI7ENt2SyQo", ".f8c2h.20/v[]20vug23bm", "This is some other contents that should be the same")]
  public async Task AesEncryptionTests_DecryptAsync_BytesDecrypted(string encryptedContents, string encodedPassword, string expectedContents)
  {
    var encryptedBytes = Convert.FromBase64String(encryptedContents);

    var passwordBytes = System.Text.Encoding.UTF8.GetBytes(encodedPassword);
    byte[] outputBytes = await _encryption.DecryptAsync(encryptedBytes, passwordBytes);

    Assert.NotNull(outputBytes);
    Assert.NotEmpty(outputBytes);

    var outputContents = System.Text.Encoding.UTF8.GetString(outputBytes);
    Assert.Equal(expectedContents, outputContents);
  }

  [Theory]
  [InlineData("CjM5lgRAUVdW88HvlzYEt2RliGhRmz1KqCXQ0UiAi18JufFGWkA1o9NlCPRHGONp", "123", "TEST BYTES")]
  [InlineData("yyhreYacU8Fm4PDCMNfrPAXTyDo6uFbPfHkHGzzE2j8vbkzr7827LHsfuq2OBbhM3BpWSrDw25j46sRpBhjr3FRN/aX2siPcoIK5Ss+4sD+n+ynWvV3L6vI7ENt2SyQo", ".f8c2h.20/v[]20vug23bm", "This is some other contents that should be the same")]
  public async Task AesEncryptionTests_DecryptFileAsync_FileDecrypted(string encryptedContents, string encodedPassword, string expectedContents)
  {
    var encryptedBytes = Convert.FromBase64String(encryptedContents);
    var passwordBytes = System.Text.Encoding.UTF8.GetBytes(encodedPassword);

    await InitializeFilesAsync(encryptedBytes);
    await _encryption.DecryptFileAsync(_testInputFilepath, _testOutputFilepath, passwordBytes);

    var outputBytes = await File.ReadAllBytesAsync(_testOutputFilepath);

    Assert.NotNull(outputBytes);
    Assert.NotEmpty(outputBytes);
    Assert.Equal(expectedContents, System.Text.Encoding.UTF8.GetString(outputBytes));
  }

  private string GetBase64(byte[] bytes)
  {
    return Convert.ToBase64String(bytes);
  }

  private async Task InitializeFilesAsync(byte[] contents)
  {
    if (!Directory.Exists(TEST_FILE_DIRECTORY))
    {
      Directory.CreateDirectory(TEST_FILE_DIRECTORY);
    }

    if (File.Exists(_testOutputFilepath))
    {
      File.Delete(_testOutputFilepath);
    }

    if (File.Exists(_testInputFilepath))
    {
      File.Delete(_testInputFilepath);
    }

    await File.WriteAllBytesAsync(_testInputFilepath, contents);
  }
}