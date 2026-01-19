using System;
using System.IO;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

class PasswordManager
{
    // ================= FILES =================
    static string vaultFile = "vault.txt";
    static string configFile = "config.txt";
    static string masterFile = "master.cfg";

    // ================= KEYS =================
    static string masterKey = "MASTER-KEY-CHANGE-THIS";
    static string passwordKey = "PASSWORD-KEY-CHANGE-THIS";

    // ================= DATA =================
    static Dictionary<string, string> vault = new Dictionary<string, string>();
    static string language = "RU";

    // ================= CRYPTO CORE =================

    static byte[] GetKey(string key)
    {
        using SHA256 sha = SHA256.Create();
        return sha.ComputeHash(Encoding.UTF8.GetBytes(key));
    }

    // AES WITH RANDOM IV (STORED IN FILE)
    static string EncryptAES(string text, string key)
    {
        using Aes aes = Aes.Create();
        aes.Key = GetKey(key);
        aes.GenerateIV();

        using MemoryStream ms = new MemoryStream();
        ms.Write(aes.IV, 0, aes.IV.Length);

        using CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write);
        using StreamWriter sw = new StreamWriter(cs);
        sw.Write(text);
        sw.Close();

        return Convert.ToBase64String(ms.ToArray());
    }

    static string DecryptAES(string encrypted, string key)
    {
        byte[] fullData = Convert.FromBase64String(encrypted);

        using Aes aes = Aes.Create();
        aes.Key = GetKey(key);

        byte[] iv = new byte[16];
        Array.Copy(fullData, iv, 16);
        aes.IV = iv;

        using MemoryStream ms = new MemoryStream();
        ms.Write(fullData, 16, fullData.Length - 16);
        ms.Position = 0;

        using CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read);
        using StreamReader sr = new StreamReader(cs);
        return sr.ReadToEnd();
    }

    // ================= HASH =================

    static string Hash(string input)
    {
        using SHA256 sha = SHA256.Create();
        return Convert.ToBase64String(sha.ComputeHash(Encoding.UTF8.GetBytes(input)));
    }

    // ================= INPUT =================

    static string ReadHidden()
    {
        StringBuilder input = new StringBuilder();
        ConsoleKey key;

        while ((key = Console.ReadKey(true).Key) != ConsoleKey.Enter)
        {
            if (key == ConsoleKey.Backspace && input.Length > 0)
            {
                input.Remove(input.Length - 1, 1);
                Console.Write("\b \b");
            }
            else if (!char.IsControl((char)key))
            {
                input.Append((char)key);
                Console.Write("*");
            }
        }
        Console.WriteLine();
        return input.ToString();
    }

    // ================= LANGUAGE =================

    static void LoadLanguage()
    {
        if (File.Exists(configFile))
            language = File.ReadAllText(configFile).Trim();
        else
            ChooseLanguage();
    }

    static void SaveLanguage()
    {
        File.WriteAllText(configFile, language);
    }

    static void ChooseLanguage()
    {
        Console.WriteLine("Choose language / Выберите язык");
        Console.WriteLine("1. Русский");
        Console.WriteLine("2. English");
        Console.Write("Choice / Выбор: ");

        string? choice = Console.ReadLine();
        language = choice == "2" ? "EN" : "RU";
        SaveLanguage();
    }

    static string T(string ru, string en)
    {
        return language == "RU" ? ru : en;
    }

    // ================= MASTER PASSWORD =================

    static void SetupMasterPassword()
    {
        Console.WriteLine("\n=== CREATE MASTER PASSWORD ===");
        Console.WriteLine("Создайте мастер-пароль / Create master password:");

        string pass1 = ReadHidden();
        Console.WriteLine("Повторите пароль / Repeat password:");
        string pass2 = ReadHidden();

        if (pass1 != pass2 || pass1.Length < 4)
        {
            Console.WriteLine("Пароли не совпадают или слишком короткие!");
            SetupMasterPassword();
            return;
        }

        string hashed = Hash(pass1);
        string encryptedHash = EncryptAES(hashed, masterKey);

        File.WriteAllText(masterFile, encryptedHash);
        Console.WriteLine("Мастер-пароль сохранён и защищён!");
    }

    static bool CheckMasterPassword()
    {
        try
        {
            string encryptedHash = File.ReadAllText(masterFile);
            string storedHash = DecryptAES(encryptedHash, masterKey);

            Console.WriteLine("\nВведите мастер-пароль / Enter master password:");
            string input = ReadHidden();

            return Hash(input) == storedHash;
        }
        catch
        {
            Console.WriteLine("\nФайл мастер-пароля повреждён!");
            Console.WriteLine("Master file corrupted!");
            File.Delete(masterFile);
            SetupMasterPassword();
            return true;
        }
    }

    // ================= PASSWORD =================

    static string GeneratePassword(int length)
    {
        const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+<>?";
        Random rnd = new Random();
        StringBuilder pass = new StringBuilder();

        for (int i = 0; i < length; i++)
            pass.Append(chars[rnd.Next(chars.Length)]);

        return pass.ToString();
    }

    // ================= STORAGE =================

    static void SaveVault()
    {
        StringBuilder data = new StringBuilder();

        foreach (var entry in vault)
        {
            data.AppendLine("SERVICE:" + entry.Key);
            data.AppendLine("PASSWORD:" + entry.Value);
            data.AppendLine("---");
        }

        File.WriteAllText(vaultFile, data.ToString());
    }

    static void LoadVault()
    {
        if (!File.Exists(vaultFile))
            return;

        string[] lines = File.ReadAllLines(vaultFile);
        string service = "";

        foreach (string line in lines)
        {
            if (line.StartsWith("SERVICE:"))
                service = line.Replace("SERVICE:", "");
            else if (line.StartsWith("PASSWORD:"))
                vault[service] = line.Replace("PASSWORD:", "");
        }
    }

    // ================= FEATURES =================

    static void AddService()
    {
        Console.Write(T("Введите сервис: ", "Enter service: "));
        string service = Console.ReadLine() ?? "";

        Console.Write(T("Введите длину пароля: ", "Enter password length: "));
        if (!int.TryParse(Console.ReadLine(), out int length) || length < 4)
        {
            Console.WriteLine(T("Некорректная длина!", "Invalid length!"));
            return;
        }

        string password = GeneratePassword(length);
        vault[service] = EncryptAES(password, passwordKey);
        SaveVault();

        Console.WriteLine(T("\nПароль создан и сохранён!", "\nPassword created and saved!"));
        Console.WriteLine(T("Пароль: ", "Password: ") + password);
    }

    static void GetService()
    {
        Console.Write(T("Введите сервис: ", "Enter service: "));
        string service = Console.ReadLine() ?? "";

        if (!vault.ContainsKey(service))
        {
            Console.WriteLine(T("Сервис не найден!", "Service not found!"));
            return;
        }

        string password = DecryptAES(vault[service], passwordKey);
        Console.WriteLine(T("Пароль: ", "Password: ") + password);
    }

    // ================= MAIN =================

    static void Main()
    {
        if (!File.Exists(masterFile))
            SetupMasterPassword();
        else if (!CheckMasterPassword())
        {
            Console.WriteLine("Доступ запрещён / Access denied");
            return;
        }

        LoadLanguage();
        LoadVault();

        while (true)
        {
            Console.WriteLine("\n=== TO-PASS ===");
            Console.WriteLine("1. " + T("Добавить сервис", "Add service"));
            Console.WriteLine("2. " + T("Получить пароль", "Get password"));
            Console.WriteLine("3. " + T("Сменить язык", "Change language"));
            Console.WriteLine("4. " + T("Выйти", "Exit"));
            Console.Write(T("Выбор: ", "Choice: "));

            string choice = Console.ReadLine() ?? "";

            if (choice == "1") AddService();
            else if (choice == "2") GetService();
            else if (choice == "3") ChooseLanguage();
            else if (choice == "4") break;
        }
    }
}
