using System.Security.Cryptography;
using System.Text;
using SecRev.NoSqlExport;

if (args.Length == 1 && args[0] is "--help" or "-h")
{
    PrintUsage();
    return 0;
}

if (args.Length != 3 || !Guid.TryParse(args[2], out var tenantId) || tenantId == Guid.Empty)
{
    PrintUsage();
    return 2;
}

char[]? passphraseChars = null;
string? passphrase = null;
try
{
    Console.Write("Custodian export archive passphrase: ");
    passphraseChars = ReadSecret();
    passphrase = new string(passphraseChars);
    Console.WriteLine();

    NoSqlBundleConverter.Convert(args[0], args[1], tenantId, passphrase);
    Console.WriteLine($"Validated NoSQL-compatible archive created at: {Path.GetFullPath(args[1])}");
    Console.WriteLine("Only permanently approved/rejected records were included. Plaintext originals and decrypted OCR/review content were not copied.");
    Console.WriteLine("Upload encrypted payloads to private Blob Storage first, then populate EncryptedPackagePath with the resulting URI before Cosmos DB ingestion.");
    return 0;
}
catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or
                            CryptographicException or ArgumentException or System.Text.Json.JsonException or
                            InvalidOperationException or OverflowException)
{
    Console.Error.WriteLine($"NoSQL export conversion failed: {ex.Message}");
    return 1;
}
finally
{
    if (passphraseChars is not null) Array.Clear(passphraseChars);
    passphrase = null;
}

static char[] ReadSecret()
{
    var chars = new List<char>();
    while (true)
    {
        var key = Console.ReadKey(intercept: true);
        if (key.Key == ConsoleKey.Enter) break;
        if (key.Key == ConsoleKey.Backspace)
        {
            if (chars.Count > 0) chars.RemoveAt(chars.Count - 1);
            continue;
        }
        if (!char.IsControl(key.KeyChar)) chars.Add(key.KeyChar);
    }
    return chars.ToArray();
}

static void PrintUsage()
{
    Console.WriteLine("Usage: SecRev.NoSqlExport <custodian-export-bundle-directory> <new-output-directory> <tenant-guid>");
    Console.WriteLine("Validates the signed SecRev export bundle and writes only permanently approved/rejected records.");
    Console.WriteLine("The archive passphrase is requested interactively and is not accepted as a command-line argument.");
}
