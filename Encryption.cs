using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecurityTools
{
    public class Encryption
    {
        public string Encrypt(string plainText, int slider = 1)
        {
            return new string(plainText.Select(x => (char)(x + 1)).ToArray());
        }

        public string Decrypt(string obfuscatedText, int slider = 1)
        {
            return new string(obfuscatedText.Select(x => (char)(x - 1)).ToArray());
        }

        private string EncryptByPassphrase(string plainStr, string keyString = "SK3L3T0N")
        {
            var aesEncryption = new RijndaelManaged
            {
                KeySize = 256,
                BlockSize = 128,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.ISO10126
            };
            var KeyInBytes = Encoding.UTF8.GetBytes(keyString);
            aesEncryption.Key = KeyInBytes;
            var plainText = Encoding.UTF8.GetBytes(plainStr);
            var crypto = aesEncryption.CreateEncryptor();
            var cipherText = crypto.TransformFinalBlock(plainText, 0, plainText.Length);
            return Convert.ToBase64String(cipherText);
        }

        private string DecryptByPassphrase(string encryptedText, string KeyString = "SK3L3T0N")
        {
            var aesEncryption = new RijndaelManaged
            {
                KeySize = 256,
                BlockSize = 128,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.ISO10126
            };
            var KeyInBytes = Encoding.UTF8.GetBytes(KeyString);
            aesEncryption.Key = KeyInBytes;
            var decrypto = aesEncryption.CreateDecryptor();
            var encryptedBytes = Convert.FromBase64CharArray(encryptedText.ToCharArray(), 0, encryptedText.Length);
            return Encoding.UTF8.GetString(decrypto.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length));
        }
    }
}
