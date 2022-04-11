

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using System.Text;

namespace RSACryptography
{
    internal class RSAEncryptionWithOwnX509Cert
    {
        // I used "openssl req -sha256 -newkey rsa:2048 -nodes -keyout merchant.pem -x509 -days 1440 -out merchant_x509o.cer" on my Mac to produce the following keys

        private static String myX509CertificatePEMinXML = @"<RSAKeyValue><Modulus>rhZ0QUvVZol3UJ3a86PNAnMwWNOvkEhQdda7HIeGFhIkEiM7m/suJcSQdaj8jpI4yB6UbPogUgYzdFlZxYDmeBZKdudJocO68wTJPiAJrITyHDAwcD/Kz9huLrLPsX+1rLPc1dWPxxUbpGrc4hPpLlbwf6FYJHP14o518NkgJy+v0rSeAa6Ak41qwLyAyK0Jzi/wcrHe40tBLQe6k40QftbsTxkgEkUQ7+G718f7DpQ9zb3xOfuk3J9NtCCliCk+APUOAtduOOR8rxeTOhc4eVSrXUou+tthKOTBrOqrMibplFIZKAwvgQ8TfasSRlVzZf+kY/tfxvcmlV/j98D1XQ==</Modulus><Exponent>AQAB</Exponent><P>4oUrDnw11g/a7F6Lmo9MuSpyJv+9PeDHeIlFsvya9iofDvtrrWoFVtQYnhs3v/kqwERI/AWst5M9xj1zHWXeBY3ClSrbEzFbN0iPA78EMVbAwR92LwCkjOLf+YJdAWmZGzPLNBMI30eR5PCoYSqfz8hquSDtygrPBYtshoIjhjM=</P><Q>xL5tAcBF0tcbhzPawvh18DzLiyCjX9Y14U4zheN4PSbOgfcd7Qtx+MiP7GuFku4UZsdxWDRDzrCfjtIlYfFpfcpGaNjERV7GEo4cg3Bj7vwkV16JkPWYJV20Vvfo3Tfv1C8IUmPQE2fpJL3ch3Kw17ryxCSbM+JMA45H89QxZi8=</Q><DP>id8F6uYdGnJCDJYrIGLSDu3P1v7XXx8+KZZbrupjIytWBhdvXXhnUYb8iNcGIrl0lNu7FHIbwwxCkDN8qksDTJwQ8BvKha8H1uk56szLr4AfCCyvEUKx5PJ94m6/TwnH36+xobtoLgZwvUjhI2r/JEfW9WEeelgD01seLext1NM=</DP><DQ>ssF110Zz6loJJ/GkTMtklM8X/KO97MB7GedshrSjNaSBsrHtHcftWKYZpiwXI+Vu4edKA2MRTMVLY39p+bBXMbRL/s0cnw66FnfKTl4aXjP3bO53PR73itO1m+MJT52YKQhGnl0T293ohbp/mQ1KweeY1T+RSDXO7NgkZdSgwX8=</DQ><InverseQ>ujqvtOHAzBSJuJ+nn9O/JJUlP7FfR9U1PzxHBh2x8AvmZHQ16n/E8ZExgGmnQUi4rdAL9ENurKA2DCYW7cXfIPxdLI+jUulFEUnD6I18yip7TW3vIKnDtL10YD0AUop5tVWeiTQVbyXGkpuOlgTHa4QbDzUaBOF/7JPq9jHavQY=</InverseQ><D>A9lZPqxXjonRioXC9ooTmU9ErWIYyp7esIxL3MieTVSfWYtP4RX/ojQjYYaX9usCuGH8tCAfoNCkSJlFI9nCvrr3cIOSnDIAqyja7jW1IQxbcgYavBCdAlVtsjif4PPK54OeiVfMcwFjeBIoyhLYn/6qGJhPo5awxA6USvvx+wvIgqmF9Os324gG9Q5QfznvYbdPa3CCeWFLkReyhG5YVpCHRZeiw6HE+XsVPQ54Q05dT3LXAM4+IfB/99tOxNvozZ1SiTkLOYz/TcutxHq0lPz4iVlS9Q4xHc/RgOYl47iqdHew9JwGZzfXs63LVAJYI62kIcczpKZ6PGbA0iHaXQ==</D></RSAKeyValue>";
        private static String myX509PrivateKeyInPEMFormat = @"-----BEGIN PRIVATE KEY-----
                                                            MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCuFnRBS9VmiXdQ
                                                            ndrzo80CczBY06+QSFB11rsch4YWEiQSIzub+y4lxJB1qPyOkjjIHpRs+iBSBjN0
                                                            WVnFgOZ4Fkp250mhw7rzBMk+IAmshPIcMDBwP8rP2G4uss+xf7Wss9zV1Y/HFRuk
                                                            atziE+kuVvB/oVgkc/XijnXw2SAnL6/StJ4BroCTjWrAvIDIrQnOL/Bysd7jS0Et
                                                            B7qTjRB+1uxPGSASRRDv4bvXx/sOlD3NvfE5+6Tcn020IKWIKT4A9Q4C12445Hyv
                                                            F5M6Fzh5VKtdSi7622Eo5MGs6qsyJumUUhkoDC+BDxN9qxJGVXNl/6Rj+1/G9yaV
                                                            X+P3wPVdAgMBAAECggEAA9lZPqxXjonRioXC9ooTmU9ErWIYyp7esIxL3MieTVSf
                                                            WYtP4RX/ojQjYYaX9usCuGH8tCAfoNCkSJlFI9nCvrr3cIOSnDIAqyja7jW1IQxb
                                                            cgYavBCdAlVtsjif4PPK54OeiVfMcwFjeBIoyhLYn/6qGJhPo5awxA6USvvx+wvI
                                                            gqmF9Os324gG9Q5QfznvYbdPa3CCeWFLkReyhG5YVpCHRZeiw6HE+XsVPQ54Q05d
                                                            T3LXAM4+IfB/99tOxNvozZ1SiTkLOYz/TcutxHq0lPz4iVlS9Q4xHc/RgOYl47iq
                                                            dHew9JwGZzfXs63LVAJYI62kIcczpKZ6PGbA0iHaXQKBgQDihSsOfDXWD9rsXoua
                                                            j0y5KnIm/7094Md4iUWy/Jr2Kh8O+2utagVW1BieGze/+SrAREj8Bay3kz3GPXMd
                                                            Zd4FjcKVKtsTMVs3SI8DvwQxVsDBH3YvAKSM4t/5gl0BaZkbM8s0EwjfR5Hk8Khh
                                                            Kp/PyGq5IO3KCs8Fi2yGgiOGMwKBgQDEvm0BwEXS1xuHM9rC+HXwPMuLIKNf1jXh
                                                            TjOF43g9Js6B9x3tC3H4yI/sa4WS7hRmx3FYNEPOsJ+O0iVh8Wl9ykZo2MRFXsYS
                                                            jhyDcGPu/CRXXomQ9ZglXbRW9+jdN+/ULwhSY9ATZ+kkvdyHcrDXuvLEJJsz4kwD
                                                            jkfz1DFmLwKBgQCJ3wXq5h0ackIMlisgYtIO7c/W/tdfHz4plluu6mMjK1YGF29d
                                                            eGdRhvyI1wYiuXSU27sUchvDDEKQM3yqSwNMnBDwG8qFrwfW6TnqzMuvgB8ILK8R
                                                            QrHk8n3ibr9PCcffr7Ghu2guBnC9SOEjav8kR9b1YR56WAPTWx4t7G3U0wKBgQCy
                                                            wXXXRnPqWgkn8aRMy2SUzxf8o73swHsZ52yGtKM1pIGyse0dx+1YphmmLBcj5W7h
                                                            50oDYxFMxUtjf2n5sFcxtEv+zRyfDroWd8pOXhpeM/ds7nc9HveK07Wb4wlPnZgp
                                                            CEaeXRPb3eiFun+ZDUrB55jVP5FINc7s2CRl1KDBfwKBgQC6Oq+04cDMFIm4n6ef
                                                            078klSU/sV9H1TU/PEcGHbHwC+ZkdDXqf8TxkTGAaadBSLit0Av0Q26soDYMJhbt
                                                            xd8g/F0sj6NS6UURScPojXzKKntNbe8gqcO0vXRgPQBSinm1VZ6JNBVvJcaSm46W
                                                            BMdrhBsPNRoE4X/sk+r2Mdq9Bg==
                                                            -----END PRIVATE KEY-----";

        // This is the .cer file content without th ----BEGIN CERTIFICATE---- ----END CERTIFICATE---- text
        private static String myX509CertificateCER = @"MIIDsDCCApgCCQD+QLYZSAiEwDANBgkqhkiG9w0BAQsFADCBmTELMAkGA1UEBhMC
                                                    R1IxDzANBgNVBAgMBkF0dGljYTEPMA0GA1UEBwwGQXRoZW5zMQwwCgYDVQQKDANF
                                                    UEExDzANBgNVBAsMBkVQQSBJVDEeMBwGA1UEAwwVZnlzaWtvYWVyaW9lbGxhZG9z
                                                    LmdyMSkwJwYJKoZIhvcNAQkBFhppbmZvQGZ5c2lrb2FlcmlvZWxsYWRvcy5ncjAe
                                                    Fw0yMjA0MTAxMDE3MzZaFw0yNjAzMjAxMDE3MzZaMIGZMQswCQYDVQQGEwJHUjEP
                                                    MA0GA1UECAwGQXR0aWNhMQ8wDQYDVQQHDAZBdGhlbnMxDDAKBgNVBAoMA0VQQTEP
                                                    MA0GA1UECwwGRVBBIElUMR4wHAYDVQQDDBVmeXNpa29hZXJpb2VsbGFkb3MuZ3Ix
                                                    KTAnBgkqhkiG9w0BCQEWGmluZm9AZnlzaWtvYWVyaW9lbGxhZG9zLmdyMIIBIjAN
                                                    BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArhZ0QUvVZol3UJ3a86PNAnMwWNOv
                                                    kEhQdda7HIeGFhIkEiM7m/suJcSQdaj8jpI4yB6UbPogUgYzdFlZxYDmeBZKdudJ
                                                    ocO68wTJPiAJrITyHDAwcD/Kz9huLrLPsX+1rLPc1dWPxxUbpGrc4hPpLlbwf6FY
                                                    JHP14o518NkgJy+v0rSeAa6Ak41qwLyAyK0Jzi/wcrHe40tBLQe6k40QftbsTxkg
                                                    EkUQ7+G718f7DpQ9zb3xOfuk3J9NtCCliCk+APUOAtduOOR8rxeTOhc4eVSrXUou
                                                    +tthKOTBrOqrMibplFIZKAwvgQ8TfasSRlVzZf+kY/tfxvcmlV/j98D1XQIDAQAB
                                                    MA0GCSqGSIb3DQEBCwUAA4IBAQBmnsGGLqc7IsbMYlxU2/w7UKeEDor59Lb60DoW
                                                    snZ2j7t3YwTsAWIquCOyduGQVLiPR5/wy+LcSVuAf34NA0z/K+oQmqgqAhFAtZqy
                                                    bP52yzNiA2rAdh5E70yYSp9mSekvcxN5ozbWIYwJzb7Wih2cPWj5llWSBpIGp3CM
                                                    g0gLNGeXNO2MbeLIIs0td2bm5ufPKqBUzYgXv5XqPcGMYEARibzXoArmo3UpzeVw
                                                    WJgGwOYYO++7WhOFCuH0ZneFUtGVAAjzSoTEJz5AKXhZUq8FjLJ9zMILEiGelvBa
                                                    yihzicf67VSwAMgaN3/oPOiS57iF7tZ0K67nWdppF/cnwfnP";

        public static string sign(string valueToSign)
        {
            //byte[] keyBytes = Encoding.Unicode.GetBytes(myX509Certificate);
            byte[] toSign = System.Text.Encoding.Unicode.GetBytes(valueToSign);

            RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();
            RSAalg.ImportFromPem(myX509PrivateKeyInPEMFormat.ToCharArray());
            byte[] signature = RSAalg.SignData(toSign, "SHA256");
            string sgStr = Convert.ToBase64String(signature);

            return sgStr;
        }

        // This method is used when the PEM certificate has been transformed to XML from an external tool
        public static string sign2(string valueToSign)
        {

            RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
            provider.FromXmlString(myX509CertificatePEMinXML);
            byte[] signedBytes = provider.SignData(Encoding.Unicode.GetBytes(valueToSign), "SHA256");

            return Convert.ToBase64String(signedBytes);

        }

        // This method uses BouncyCastle library to transform the PEM private key into XML first (PEM2XML)
        public static string sign3(string valueToSign)
        {

            RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
            provider.FromXmlString(PEM2XML(myX509PrivateKeyInPEMFormat));
            byte[] signedBytes = provider.SignData(Encoding.Unicode.GetBytes(valueToSign), "SHA256");

            return Convert.ToBase64String(signedBytes);

        }

        public static string PEM2XML(string PEM)
        {
            PemReader pemReader = new PemReader(new StringReader(PEM));
            RsaPrivateCrtKeyParameters keyPair = (RsaPrivateCrtKeyParameters)pemReader.ReadObject();
            AsymmetricKeyParameter privateKey = keyPair;
            RSA rsa = DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)privateKey);
            string xmlRsa = rsa.ToXmlString(true);

            return xmlRsa;
        }

    }
}
