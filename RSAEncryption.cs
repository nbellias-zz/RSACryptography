﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Serialization;

namespace RSACryptography
{
    internal class RSAEncryption
    {
        private static RSACryptoServiceProvider csp = new RSACryptoServiceProvider(2048);
        private RSAParameters _privateKey;
        private RSAParameters _publicKey;

        public RSAEncryption()
        {
            _privateKey = csp.ExportParameters(true);
            _publicKey = csp.ExportParameters(false);
        }

        public string GetPublicKey()
        {
            var sw = new StringWriter();
            var xs = new XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, _publicKey);

            return sw.ToString();
        }

        public string Encrypt(string plainText)
        {
            csp = new RSACryptoServiceProvider();
            csp.ImportParameters(_publicKey);
            var data = Encoding.Unicode.GetBytes(plainText);
            var cypher = csp.Encrypt(data, false);

            return Convert.ToBase64String(cypher);
        }

        public string Decrypt(string cypherText)
        {
            var dataBytes = Convert.FromBase64String(cypherText);
            csp.ImportParameters(_privateKey);
            var plainText = csp.Decrypt(dataBytes, false);

            return Encoding.Unicode.GetString(plainText);
        }

    }
}
