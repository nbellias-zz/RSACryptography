// See https://aka.ms/new-console-template for more information
using RSACryptography;

Console.WriteLine("This is our RSA Encryption program");
Console.WriteLine();

//RSAEncryption rsa = new RSAEncryption();
//string cypher = String.Empty;

//Console.WriteLine($"Public Key is: {rsa.GetPublicKey()}\n");

//Console.WriteLine("Enter your text to encrypt");
//var text = Console.ReadLine();
//if (!string.IsNullOrEmpty(text))
//{
//    cypher = rsa.Encrypt(text);
//    Console.WriteLine($"Encrypted text is: {cypher}\n");
//}

//Console.WriteLine("Press any key to decrypt text");
//Console.ReadLine();
//var plainText = rsa.Decrypt(cypher);

//Console.WriteLine();
//Console.WriteLine(plainText);

RSAEncryptionWithOwnX509Cert rsaX509 = new RSAEncryptionWithOwnX509Cert();

Console.WriteLine(RSAEncryptionWithOwnX509Cert.sign("Hello World"));
Console.WriteLine();
Console.WriteLine();
Console.WriteLine(RSAEncryptionWithOwnX509Cert.sign2("Hello World"));
Console.WriteLine();
Console.WriteLine();
Console.WriteLine(RSAEncryptionWithOwnX509Cert.sign3("Hello World"));
