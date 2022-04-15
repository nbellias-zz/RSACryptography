

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
        // The xml was produced with an external online tool https://the-x.cn/en-US/certificate/PemToXml.aspx
        private static String myX509CertificatePEMinXML = @"<RSAKeyValue>
  <D>q+RiG6tutURSV6FFHnNGLMofqh6xZeRGDQdJM9LNYi7Vt1ZGa/2rWE1GQ5bD886DAyzosYEZXT8Tfwd6scV3DKy//bJNNkLXuwNbxOQBtrRK7hMzLud4zhf5ZJWo6y6EpZGIkzqyDdKp2kjumsshIZV8ypCu3uC4P6XgXTmY92z448B263NVlTqZQz4XzLfwAYxzUXBoA6CKwV8KAww5JZBP98z3dHfwyU+K30KvSNbJRVxP31ETd40Rxwhk02t53hbtB30G6j9bdV1zM91tyQmcRrBRGOIBKCN6g2aV247x0ALrOwQTPZ+Do5pLpUEbZ0PcBB1axaYjyJrT0DwgIQ==</D>
  <DP>rJ1jHs5pu+WzSOPIJ3vEt9bFT8tmrnx1a2O64FCPDUzg987r6yni7CENUUOrPcyL8kQslxDYCCMK/uxprZmt3rObDuCBq7u4nvdpbpIxQ9+LT3iDev8n/aJIP6fBzlyJcqzh5m2iz/XvQEo5ybCcfGEU9sUmy3eHh0etZgjNYrU=</DP>
  <DQ>OcTna69WbLjM7p8vY2aALB/6tokizq/0OQFBI0vPkWE02P7DlVrWngoxNgZEsY9B51iMouBHWPo8eBeqHJrlksvO9/htZYLDMevWsS8UQrYhx+kqD1+PQv749sWvsyi6DwNt+QyPnxMC+/DRTkOQxqiJxO4hgSdcxpU/5JDTrFE=</DQ>
  <Exponent>AQAB</Exponent>
  <InverseQ>1QdnPEtQbR1QuNNPF8jCcA9cU5/SgQgChX3zY0ny7yzEq/erS8Y/aLW/BeDWrgkOHNbetwsGA4ngTxq3Xdk7Px2EZX9YHUd7uZQqCdsfr7Q4LORZciPu6dIS+NzcDRHxCPCMCRqEWLU/RzCQwIIufBNdzcVsojSONUdi/N5iT78=</InverseQ>
  <Modulus>9e31tLqyczMHJctCI+o65MpbYERKcb0adVu3hW3uIglD9Bt2G1Q+096pQ12uI/Lqee7dSoYQ1cH7LAcBs0p2XmQ1X87hdgnbvWw3u0fP6G1SzFKEoXuJK96qlJMxBdv/Mhp3/i9pBP6j4EtXFi4PtUhyrgF45atk1p3bhfoTu9Y2xiLW7iPRKlrMpvf/goVM5uiknhf81c0Lrp2D6U1wziAGaA74dtiA61hHgW4FYYTfmeI5/E/3TnMsRhmPsJ+mwtPO51i0Sb8TcmAalLdXCN32CFztwID4JLRTh4KjcOauJl1SUcp7t9Uje09BgScQa4VYQ2RASZJ4JYmts6bLFw==</Modulus>
  <P>+3K/Ahdg005qwxNun7AiV/Gwq80ZPao8yvCvAbFEdo9EqUr15Q/L3e1eBqEC7t8WMju9d2YiFAYpxuPny042vc8kmhBp3GkK0LE3ZjRTYkYHnoPqH8/Dti1w3plNEW/D0QM5UZUxBik3CVQxI8Jal8bVPkvkjeFQHzkZTuOxoec=</P>
  <Q>+mGjmwIEO8izUFXV9J8AD7a09SUvLmJpwvmeqUh+DDyUaaMhm7aXM1zZUYJ1Y/ACR2KMv0IDpPFhRNtiN0+Ou4Hd5ieJuazRRH/vJ6nQ/54EVbdV5T53Q9fF/kASTH9Vvx1983sTg6RovuaB5/CtzuQflSKydwiDv8SEBIyox1E=</Q>
</RSAKeyValue>";
        private static String myX509PrivateKeyInPEMFormat = @"-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQD17fW0urJzMwcl
y0Ij6jrkyltgREpxvRp1W7eFbe4iCUP0G3YbVD7T3qlDXa4j8up57t1KhhDVwfss
BwGzSnZeZDVfzuF2Cdu9bDe7R8/obVLMUoShe4kr3qqUkzEF2/8yGnf+L2kE/qPg
S1cWLg+1SHKuAXjlq2TWnduF+hO71jbGItbuI9EqWsym9/+ChUzm6KSeF/zVzQuu
nYPpTXDOIAZoDvh22IDrWEeBbgVhhN+Z4jn8T/dOcyxGGY+wn6bC087nWLRJvxNy
YBqUt1cI3fYIXO3AgPgktFOHgqNw5q4mXVJRynu31SN7T0GBJxBrhVhDZEBJkngl
ia2zpssXAgMBAAECggEBAKvkYhurbrVEUlehRR5zRizKH6oesWXkRg0HSTPSzWIu
1bdWRmv9q1hNRkOWw/POgwMs6LGBGV0/E38HerHFdwysv/2yTTZC17sDW8TkAba0
Su4TMy7neM4X+WSVqOsuhKWRiJM6sg3SqdpI7prLISGVfMqQrt7guD+l4F05mPds
+OPAdutzVZU6mUM+F8y38AGMc1FwaAOgisFfCgMMOSWQT/fM93R38MlPit9Cr0jW
yUVcT99RE3eNEccIZNNred4W7Qd9Buo/W3VdczPdbckJnEawURjiASgjeoNmlduO
8dAC6zsEEz2fg6OaS6VBG2dD3AQdWsWmI8ia09A8ICECgYEA+3K/Ahdg005qwxNu
n7AiV/Gwq80ZPao8yvCvAbFEdo9EqUr15Q/L3e1eBqEC7t8WMju9d2YiFAYpxuPn
y042vc8kmhBp3GkK0LE3ZjRTYkYHnoPqH8/Dti1w3plNEW/D0QM5UZUxBik3CVQx
I8Jal8bVPkvkjeFQHzkZTuOxoecCgYEA+mGjmwIEO8izUFXV9J8AD7a09SUvLmJp
wvmeqUh+DDyUaaMhm7aXM1zZUYJ1Y/ACR2KMv0IDpPFhRNtiN0+Ou4Hd5ieJuazR
RH/vJ6nQ/54EVbdV5T53Q9fF/kASTH9Vvx1983sTg6RovuaB5/CtzuQflSKydwiD
v8SEBIyox1ECgYEArJ1jHs5pu+WzSOPIJ3vEt9bFT8tmrnx1a2O64FCPDUzg987r
6yni7CENUUOrPcyL8kQslxDYCCMK/uxprZmt3rObDuCBq7u4nvdpbpIxQ9+LT3iD
ev8n/aJIP6fBzlyJcqzh5m2iz/XvQEo5ybCcfGEU9sUmy3eHh0etZgjNYrUCgYA5
xOdrr1ZsuMzuny9jZoAsH/q2iSLOr/Q5AUEjS8+RYTTY/sOVWtaeCjE2BkSxj0Hn
WIyi4EdY+jx4F6ocmuWSy873+G1lgsMx69axLxRCtiHH6SoPX49C/vj2xa+zKLoP
A235DI+fEwL78NFOQ5DGqInE7iGBJ1zGlT/kkNOsUQKBgQDVB2c8S1BtHVC4008X
yMJwD1xTn9KBCAKFffNjSfLvLMSr96tLxj9otb8F4NauCQ4c1t63CwYDieBPGrdd
2Ts/HYRlf1gdR3u5lCoJ2x+vtDgs5FlyI+7p0hL43NwNEfEI8IwJGoRYtT9HMJDA
gi58E13NxWyiNI41R2L83mJPvw==
-----END PRIVATE KEY-----";

        // This is the .cer file content without th ----BEGIN CERTIFICATE---- ----END CERTIFICATE---- text
        private static String myX509CertificateCER = @"MIIESzCCAzOgAwIBAgIJANq6Drpt8SB5MA0GCSqGSIb3DQEBCwUAMHYxCzAJBgNV
BAYTAkVFMREwDwYDVQQIEwhIYXJqdW1hYTEQMA4GA1UEBxMHVGFsbGlubjEQMA4G
A1UEChMHTW9kaXJ1bTEUMBIGA1UECxMLRGV2ZWxvcG1lbnQxGjAYBgNVBAMTEWlu
dGVyZmFjZTRTaWdua2V5MB4XDTE3MTExNjE0MDUwN1oXDTMxMDcyNjE0MDUwN1ow
djELMAkGA1UEBhMCRUUxETAPBgNVBAgTCEhhcmp1bWFhMRAwDgYDVQQHEwdUYWxs
aW5uMRAwDgYDVQQKEwdNb2RpcnVtMRQwEgYDVQQLEwtEZXZlbG9wbWVudDEaMBgG
A1UEAxMRaW50ZXJmYWNlNFNpZ25rZXkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQD17fW0urJzMwcly0Ij6jrkyltgREpxvRp1W7eFbe4iCUP0G3YbVD7T
3qlDXa4j8up57t1KhhDVwfssBwGzSnZeZDVfzuF2Cdu9bDe7R8/obVLMUoShe4kr
3qqUkzEF2/8yGnf+L2kE/qPgS1cWLg+1SHKuAXjlq2TWnduF+hO71jbGItbuI9Eq
Wsym9/+ChUzm6KSeF/zVzQuunYPpTXDOIAZoDvh22IDrWEeBbgVhhN+Z4jn8T/dO
cyxGGY+wn6bC087nWLRJvxNyYBqUt1cI3fYIXO3AgPgktFOHgqNw5q4mXVJRynu3
1SN7T0GBJxBrhVhDZEBJknglia2zpssXAgMBAAGjgdswgdgwHQYDVR0OBBYEFIma
dY2XUUEADcnAi2qwi433Npp+MIGoBgNVHSMEgaAwgZ2AFImadY2XUUEADcnAi2qw
i433Npp+oXqkeDB2MQswCQYDVQQGEwJFRTERMA8GA1UECBMISGFyanVtYWExEDAO
BgNVBAcTB1RhbGxpbm4xEDAOBgNVBAoTB01vZGlydW0xFDASBgNVBAsTC0RldmVs
b3BtZW50MRowGAYDVQQDExFpbnRlcmZhY2U0U2lnbmtleYIJANq6Drpt8SB5MAwG
A1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAL0bSHmsVF/Pys1vLmehFIvk
jopF2plRVklCalMiy+IJx8N9A91PsCbc2veykvIlFtEwVoVZGPtSlNDUl9HsSH/A
zcatBRWe/Iz1W/4rMa1UWZsk2DDw6bjvo1KPYIvHBufUB4IXm/qyFL7IohYcWF/s
w0y+XMrvcd3c7ClZ1mq43GKnlHkXwaPWHoMnuviguIbgKAHKVT9pgqCZQSoIjN08
oejCa7qVlYuUY5EGwzuHNErntmcgicP7sLWd4Pu1fAx+51tgDSGjh2m0SSDz2rv7
CrJ44RXIUOWAMWbC4myssyea3t+GrSvWrDGHRLXZUNmvy+zFSB+QFWEW2nlfYI8=";

        public static string sign(string valueToSign)
        {
            //byte[] keyBytes = Encoding.Unicode.GetBytes(myX509Certificate);
            byte[] toSign = System.Text.Encoding.UTF8.GetBytes(valueToSign);

            RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();
            RSAalg.ImportFromPem(myX509PrivateKeyInPEMFormat.ToCharArray());
            byte[] signature = RSAalg.SignData(toSign, SHA256.Create());
            string sgStr = Convert.ToBase64String(signature);

            return sgStr;
        }

        // This method is used when the PEM certificate has been transformed to XML from an external tool
        public static string sign2(string valueToSign)
        {

            RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
            provider.FromXmlString(myX509CertificatePEMinXML);
            byte[] signedBytes = provider.SignData(Encoding.UTF8.GetBytes(valueToSign), SHA256.Create());

            return Convert.ToBase64String(signedBytes);

        }

        // This method uses BouncyCastle library to transform the PEM private key into XML first (PEM2XML)
        public static string sign3(string valueToSign)
        {

            RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
            provider.FromXmlString(PEM2XML(myX509PrivateKeyInPEMFormat));
            byte[] signedBytes = provider.SignData(Encoding.UTF8.GetBytes(valueToSign), SHA256.Create());

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
