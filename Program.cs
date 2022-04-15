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

//**************************************************************************
string sessionID = Guid.NewGuid().ToString("N").ToUpper();
string version = "4.0";
string cardNumber = "4016360000000010";
string expirationDate = "2206";
string deviceCategory = "0";
string cardAmount = "5";
string exponent = "2";
string description = "Test http post MPI request";
string currency = "978";
string MID = "0022007645";
string xid = "aTb+aVdPcawghwB9k4J1B5/hAG8=";
string merchantTxId = Guid.NewGuid().ToString("D"); //"221f3245-88d8-4a1f-ab7e-5348567999e5"; // 
string okUrl = $"https://alphaecommerce-test.cardlink.gr:443/coffeehouse/MerchantHandler2;jsessionid={sessionID}?resultUrl=OK";
string failUrl = $"https://alphaecommerce-test.cardlink.gr:443/coffeehouse/MerchantHandler2;jsessionid={sessionID}?resultUrl=FAIL";
string MD = sessionID;
string city = "City";
string streetNum = "300";
string street = "Street";
string zipCode = "12345";
string valueToSignForSignature = $"{version};{cardNumber};{expirationDate};{deviceCategory};{cardAmount};{exponent};{description};{currency};{MID};{xid};{merchantTxId};{okUrl};{failUrl};{MD};{city};{streetNum};{street};{zipCode};";

RSAEncryptionWithOwnX509Cert rsaX509 = new RSAEncryptionWithOwnX509Cert();
Console.WriteLine($"SESSIONID = {sessionID}");
Console.WriteLine();
Console.WriteLine($"merchantTxId = {merchantTxId}");
Console.WriteLine();
Console.WriteLine("Signature below:");
Console.WriteLine();
//Console.WriteLine(RSAEncryptionWithOwnX509Cert.sign(valueToSignForSignature));
//Console.WriteLine();
//Console.WriteLine();
//Console.WriteLine(RSAEncryptionWithOwnX509Cert.sign2(valueToSignForSignature));
//Console.WriteLine();
//Console.WriteLine();
Console.WriteLine(RSAEncryptionWithOwnX509Cert.sign3(valueToSignForSignature));
