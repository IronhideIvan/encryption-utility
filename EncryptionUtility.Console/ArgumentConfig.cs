using System;

namespace EncryptionUtility.Console
{
  public class ArgumentConfig
  {
    public InputType InputType = InputType.RawString;
    public ProcessingType ProcessingType = ProcessingType.Unknown;
    public Verbosity Verbosity = Verbosity.Silent;
    public string Input = string.Empty;
    public string Password = string.Empty;
  }
}
