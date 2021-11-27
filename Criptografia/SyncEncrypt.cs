using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Criptografia
{
    public class SyncEncrypt
    {
        public SyncEncrypt()
        {

        }


        public static string EncriptarAES(string key, string text, string vi)
        {
            if (String.IsNullOrEmpty(key) || String.IsNullOrEmpty(text) || String.IsNullOrEmpty(vi))
                throw new ArgumentException("Todos os parâmetros são obrigatórios.");

            byte[] arrTextoCriptado = null;
            byte[] arrKey = ASCIIEncoding.UTF8.GetBytes(key);
            byte[] arrVI = ASCIIEncoding.UTF8.GetBytes(vi);

            using (Aes aes = Aes.Create())
            {
                aes.Key = arrKey;
                aes.IV = arrVI;

                ICryptoTransform codificadorTransform = aes.CreateEncryptor();

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream streamCrypto = new CryptoStream(ms, codificadorTransform, CryptoStreamMode.Write))
                    {
                        using (StreamWriter sw = new StreamWriter(streamCrypto, Encoding.UTF8))
                        {
                            sw.Write(text);
                        }

                        arrTextoCriptado = ms.ToArray();
                    }
                }
            }

            string base64Criptado = Convert.ToBase64String(arrTextoCriptado);

            return base64Criptado;
        }


        public static string DecriptarAES(string key, string base64Encrypt, string vi)
        {
            if (String.IsNullOrEmpty(key) || String.IsNullOrEmpty(base64Encrypt) || String.IsNullOrEmpty(vi))
                throw new ArgumentException("Todos os parâmetros são obrigatórios.");

            string textoDecriptado = String.Empty;
            byte[] arrKey = ASCIIEncoding.UTF8.GetBytes(key);
            byte[] arrVI = ASCIIEncoding.UTF8.GetBytes(vi);

            using (Aes aes = Aes.Create())
            {
                aes.Key = arrKey;
                aes.IV = arrVI;

                ICryptoTransform decodificadorTransform = aes.CreateDecryptor();

                byte[] arrTextoCifrado = Convert.FromBase64String(base64Encrypt);

                using (MemoryStream ms = new MemoryStream(arrTextoCifrado))
                {
                    using (CryptoStream streamCrypto = new CryptoStream(ms, decodificadorTransform, CryptoStreamMode.Read))
                    {
                        using (StreamReader sr = new StreamReader(streamCrypto, Encoding.UTF8))
                        {
                            textoDecriptado = sr.ReadToEnd();
                        }
                    }
                }
            }

            return textoDecriptado;

        }
    }
}
