/*
 * CTF Challenge: .NET Decompilation
 *
 * Build (Mono): mcs -out:CrackMe.exe CrackMe.cs
 * Build (.NET): dotnet build  (or csc CrackMe.cs)
 * Run: mono CrackMe.exe  (or dotnet run)
 *
 * .NET binaries contain rich metadata and are easily decompiled with:
 *   - dnSpy (Windows)
 *   - ILSpy
 *   - dotPeek (JetBrains)
 *   - monodis (Linux)
 *
 * VULNERABILITY: .NET IL is trivially decompilable to near-original source.
 * The obfuscation here (base64 + XOR) is visible in the decompiled code.
 * Extract the base64 key, XOR it with the stored bytes, recover the password.
 */

using System;
using System.Text;

namespace CrackMe
{
    class Program
    {
        /* VULNERABILITY: Base64-encoded XOR key - visible in decompiled IL.
         * Decode this to get the XOR key bytes. */
        private static readonly string ObfuscatedKey = "UzNjcjN0S2V5";
        /* ^^^ Base64 decodes to: S3cr3tKey */

        /* VULNERABILITY: These bytes XOR'd with the decoded key = password.
         * password[i] = encryptedPassword[i] ^ keyBytes[i % keyLen]
         * Result: cr4ckm3! */
        private static readonly byte[] EncryptedPassword = new byte[] {
            0x30, 0x56, 0x51, 0x40, 0x28, 0x5E, 0x56, 0x4C
        };

        /* VULNERABILITY: Flag is also base64 encoded in the binary.
         * Decompilers will show this string directly. */
        private static readonly string EncodedFlag =
            "emVtaXtkMHRuM3RfMXNfMzRzeV90MF9yM3Z9";
        /* ^^^ Base64 decodes to: zemi{d0tn3t_1s_34sy_t0_r3v} */

        static string DecryptPassword()
        {
            /* Decode the XOR key from base64 */
            byte[] keyBytes = Convert.FromBase64String(ObfuscatedKey);

            /* XOR encrypted password with key to get plaintext */
            char[] password = new char[EncryptedPassword.Length];
            for (int i = 0; i < EncryptedPassword.Length; i++)
            {
                password[i] = (char)(EncryptedPassword[i] ^ keyBytes[i % keyBytes.Length]);
            }

            return new string(password);
        }

        static bool ValidateInput(string input)
        {
            string password = DecryptPassword();

            /* Additional obfuscation: compare character by character
             * to avoid simple string comparison in decompiled output */
            if (input.Length != password.Length)
                return false;

            int result = 0;
            for (int i = 0; i < input.Length; i++)
            {
                /* VULNERABILITY: Constant-time comparison attempt,
                 * but the XOR accumulation is visible in decompiled code */
                result |= input[i] ^ password[i];
            }

            return result == 0;
        }

        static void PrintFlag()
        {
            /* Decode flag from base64 */
            byte[] flagBytes = Convert.FromBase64String(EncodedFlag);
            string flag = Encoding.UTF8.GetString(flagBytes);

            Console.WriteLine("[+] Access Granted!");
            Console.WriteLine("[+] Flag: " + flag);
        }

        static void Main(string[] args)
        {
            Console.WriteLine("=== .NET CrackMe v2.0 ===");
            Console.Write("Enter password: ");

            string input = Console.ReadLine();

            if (string.IsNullOrEmpty(input))
            {
                Console.WriteLine("[-] No input provided.");
                return;
            }

            if (ValidateInput(input))
            {
                PrintFlag();
            }
            else
            {
                Console.WriteLine("[-] Wrong password.");
                Console.WriteLine("[-] Hint: Have you tried decompiling with dnSpy or ILSpy?");
            }
        }
    }
}
