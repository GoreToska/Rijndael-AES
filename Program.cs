using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class RijndaelAlgorithm
{
    public static string Encrypt(string plainText, string passPhrase, string saltValue, string hashAlgorithm,
        int passwordIterations, string initVector, int keySize)
    {
        //Преобразование строк в байтовые массивы. Предположительно используется только ASCII
        byte[] initVectorBytes = Encoding.ASCII.GetBytes(initVector);
        byte[] saltValueBytes = Encoding.ASCII.GetBytes(saltValue);

        //Преобразование открытого текста в массив байтов.
        byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);

        //Создание пароля, из которого будет получен ключ. Этот пароль будет создан из указанной парольной фразы и "соли".
        //Пароль будет создан с использованием указанного хэша алгоритма.
        //Создание пароля может выполняться в нескольких итерациях.

        PasswordDeriveBytes password = new PasswordDeriveBytes(passPhrase, saltValueBytes,
            hashAlgorithm, passwordIterations);

        //Пароль используется для создания псевдослучайных байтов для шифрования
        //ключа. Размер ключа в байтах (не в битах).
        byte[] keyBytes = password.GetBytes(keySize / 8);

        //Создание неинициализированного объекта шифрования Rijndael.
        RijndaelManaged symmetricKey = new RijndaelManaged();

        //Целесообразно установить режим шифрования "Цепочка блоков шифрования"
        symmetricKey.Mode = CipherMode.CBC;

        //Создание шифратора из существующих байтов ключа. Размер ключа определяется на основе количества байтов ключа.
        ICryptoTransform encryptor = symmetricKey.CreateEncryptor(keyBytes, initVectorBytes);

        //Определение потока памяти, который будет использоваться для хранения зашифрованных данных.
        MemoryStream memoryStream = new MemoryStream();

        //Определение криптографического потока (всегда режим записи для шифрования).
        CryptoStream cryptoStream = new CryptoStream(memoryStream,
            encryptor, CryptoStreamMode.Write);

        //Начало шифрования.
        cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);

        //Шифрование конечного блока и очистка буфера.
        cryptoStream.FlushFinalBlock();

        //Преобразование зашифрованных данных из потока памяти в массив байтов.
        byte[] cipherTextBytes = memoryStream.ToArray();

        //Закрытие потоков.
        memoryStream.Close();
        cryptoStream.Close();

        //Преобразование зашифрованных данных в строку в кодировке base64.
        string cipherText = Convert.ToBase64String(cipherTextBytes);

        //Возврат зашифрованной последовательности.
        return cipherText;
    }

    public static string Decrypt(string cipherText, string passPhrase, string saltValue,
        string hashAlgorithm, int passwordIterations, string initVector, int keySize)
    {
        //Преобразование строк, определяющих характеристики ключа шифрования, в байтовые массивы.
        byte[] initVectorBytes = Encoding.ASCII.GetBytes(initVector);
        byte[] saltValueBytes = Encoding.ASCII.GetBytes(saltValue);

        //Преобразование зашифрованного текста в массив байтов.
        byte[] cipherTextBytes = Convert.FromBase64String(cipherText);

        //Создание пароля, из которого будет получен ключ. Этот пароль будет создан из указанной парольной фразы и "соли".
        //Пароль будет создан с использованием указанного хэша алгоритма.
        //Создание пароля может выполняться в нескольких итерациях.

        PasswordDeriveBytes password = new PasswordDeriveBytes(passPhrase, saltValueBytes,
            hashAlgorithm, passwordIterations);

        //Использование пароля для создания псевдослучайных байтов для шифрования ключа. Размер ключа в байтах (не в битах).
        byte[] keyBytes = password.GetBytes(keySize / 8);

        //Создание неинициализированного объекта шифрования Rijndael.
        RijndaelManaged symmetricKey = new RijndaelManaged();

        //Установка режима шифрования "Цепочка блоков шифрования"
        symmetricKey.Mode = CipherMode.CBC;

        //Создание дешифратора из существующих байтов ключа. Размер ключа определяется на основе байтов ключа.
        ICryptoTransform decryptor = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes);

        //Определение потока памяти, который будет использоваться для хранения зашифрованных данных.
        MemoryStream memoryStream = new MemoryStream(cipherTextBytes);

        //Определение криптографического потока (режим чтения для шифрования).
        CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
        byte[] plainTextBytes = new byte[cipherTextBytes.Length];

        //Начало расшифровывания.
        int decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);

        //Закрытие потоков.
        memoryStream.Close();
        cryptoStream.Close();

        //Преобразование расшифрованных данных в строку.
        //Предположительно исходная строка открытого текста была UTF8-encoded.
        string plainText = Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);

        //Возврат расшифрованной последовательности.  
        return plainText;
    }
}

public class RijndaelTest
{
    //Однопоточный режим (на всякий случай)
    [STAThread]
    static void Main(string[] args)
    {
        Console.Write("Введите исходный текст: ");
        string plainText = Console.ReadLine();

        string passPhrase = "TestPassphrase";        //Может быть любой строкой
        string saltValue = "TestSaltValue";        // Может быть любой строкой
        string hashAlgorithm = "SHA256";             // может быть "MD5"
        int passwordIterations = 2;                //Может быть любым числом
        string initVector = "!1A3g2D4s9K556g7"; // Должно быть 16 байт
        int keySize = 256;                // Может быть 128, 192, 256

        Console.WriteLine(string.Format($"Незашифрованный текст  : {plainText}"));

        string cipherText = RijndaelAlgorithm.Encrypt(plainText, passPhrase, saltValue,
            hashAlgorithm, passwordIterations, initVector, keySize);

        Console.WriteLine(string.Format($"Зашифрованный : {cipherText}"));

        plainText = RijndaelAlgorithm.Decrypt(cipherText, passPhrase, saltValue,
            hashAlgorithm, passwordIterations, initVector, keySize);

        Console.WriteLine(string.Format($"Дешифрованный  : {plainText}"));
        Console.ReadKey();
    }
}