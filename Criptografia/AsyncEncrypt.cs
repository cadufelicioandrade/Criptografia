using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Criptografia
{
    public class AsyncEncrypt
    {
        public string ChavePublica { get; set; }
        private string ChavePrivada { get; set; }


        public AsyncEncrypt()
        {
            RSACryptoServiceProvider encryptRSA = new RSACryptoServiceProvider();
            
            this.ChavePublica = encryptRSA.ToXmlString(includePrivateParameters: false);
            this.ChavePrivada = encryptRSA.ToXmlString(includePrivateParameters: true);
        }


        public string Encriptar(string textoPlano, string chavePublicaDestinatario)
        {
            byte[] arrCifrado;
            byte[] arrTextoBytes = ASCIIEncoding.UTF8.GetBytes(textoPlano);
            RSACryptoServiceProvider encryptRSA = new RSACryptoServiceProvider();
            encryptRSA.FromXmlString(chavePublicaDestinatario);

            arrCifrado = encryptRSA.Encrypt(arrTextoBytes, fOAEP: false);

            return Convert.ToBase64String(arrCifrado);
        }

        public string Decriptar(string base64Encrypt)
        {
            byte[] arrDecifrado;
            byte[] arrEncriptado = Convert.FromBase64String(base64Encrypt);
            RSACryptoServiceProvider decryptRSA = new RSACryptoServiceProvider();
            decryptRSA.FromXmlString(ChavePrivada);

            arrDecifrado = decryptRSA.Decrypt(arrEncriptado, fOAEP: false);

            return ASCIIEncoding.UTF8.GetString(arrDecifrado);
        }
    }

}
