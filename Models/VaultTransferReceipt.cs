using System;
using System.Security.Cryptography;
using System.Text.Json;

namespace SecRev.Models;

internal sealed class VaultTransferReceipt
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Operation { get; set; } = string.Empty;
    public string CustodianAccountId { get; set; } = string.Empty;
    public string CustodianName { get; set; } = string.Empty;
    public string OccurredAtUtc { get; set; } = string.Empty;
    public int RecordCount { get; set; }
    public string ManifestSha256 { get; set; } = string.Empty;
    public string Signature { get; set; } = string.Empty;
    public string PublicKey { get; set; } = string.Empty;

    public static byte[] Payload(VaultTransferReceipt receipt) => JsonSerializer.SerializeToUtf8Bytes(new
    {
        receipt.Id,
        receipt.Operation,
        receipt.CustodianAccountId,
        receipt.CustodianName,
        receipt.OccurredAtUtc,
        receipt.RecordCount,
        receipt.ManifestSha256
    });

    public static bool Verify(VaultTransferReceipt receipt)
    {
        byte[]? payload = null;
        byte[]? publicKey = null;
        byte[]? signature = null;
        try
        {
            payload = Payload(receipt);
            publicKey = Convert.FromBase64String(receipt.PublicKey);
            signature = Convert.FromBase64String(receipt.Signature);
            using var verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo(publicKey, out var bytesRead);
            return bytesRead == publicKey.Length && verifier.KeySize == 384 &&
                   verifier.VerifyData(payload, signature, HashAlgorithmName.SHA384);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException)
        {
            return false;
        }
        finally
        {
            if (payload is not null) CryptographicOperations.ZeroMemory(payload);
            if (publicKey is not null) CryptographicOperations.ZeroMemory(publicKey);
            if (signature is not null) CryptographicOperations.ZeroMemory(signature);
        }
    }
}
