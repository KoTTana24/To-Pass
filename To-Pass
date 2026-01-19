using System;
using System.IO;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

class PasswordManager
{
    static string vaultFile = "vault.txt";
    static string configFile = "config.txt";
    static string encryptionKey = "super-secret-key-change-this";

    static Dictionary<string, string> vault = new Dictionary<string, string>();

    static string language = "RU";

    // ================= LANGUAGE =================

    static void LoadLanguage()
    {
        if (File.Exists(configFile))
        {
            language = File.ReadAllText(configFile).Trim();
        }
        else
        {
            ChooseLanguage();
        }
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

        string choice = Console.ReadLine();

        language = choice == "2" ? "EN" : "RU";
        SaveLanguage();
    }

    static string T(string ru, string en)
    {
        return language == "RU" ? ru : en;
    }

    // ================= SECURITY =================

    static string Encrypt(string text)
    {
        using Aes aes = Aes.Create();
        aes.Key = Encoding.UTF8.GetBytes(encryptionKey.PadRight(32));
        aes.IV = new byte[16];

        using MemoryStream ms = new MemoryStream();
        using CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write);
        using StreamWriter sw = new StreamWriter(cs);

        sw.Write(text);
        sw.Close();

        return Convert.ToBase64String(ms.ToArray());
    }

    static string Decrypt(string encrypted)
    {
        using Aes aes = Aes.Create();
        aes.Key = Encoding.UTF8.GetBytes(encryptionKey.PadRight(32));
        aes.IV = new byte[16];

        using MemoryStream ms = new MemoryStream(Convert.FromBase64String(encrypted));
        using CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read);
        using StreamReader sr = new StreamReader(cs);

        return sr.ReadToEnd();
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
        string service = Console.ReadLine();

        Console.Write(T("Введите длину пароля: ", "Enter password length: "));
        int length = int.Parse(Console.ReadLine());

        string password = GeneratePassword(length);
        vault[service] = Encrypt(password);

        SaveVault();

        Console.WriteLine(T("\nПароль создан и сохранён!", "\nPassword created and saved!"));
        Console.WriteLine(T("Пароль: ", "Password: ") + password);
    }

    static void GetService()
    {
        Console.Write(T("Введите сервис: ", "Enter service: "));
        string service = Console.ReadLine();

        if (!vault.ContainsKey(service))
        {
            Console.WriteLine(T("Сервис не найден!", "Service not found!"));
            return;
        }

        string password = Decrypt(vault[service]);
        Console.WriteLine(T("Пароль: ", "Password: ") + password);
    }

    // ================= MAIN =================

    static void Main()
    {
        LoadLanguage();
        LoadVault();

        while (true)
        {
            Console.WriteLine("\n=== PASSWORD MANAGER ===");
            Console.WriteLine("1. " + T("Добавить сервис", "Add service"));
            Console.WriteLine("2. " + T("Получить пароль", "Get password"));
            Console.WriteLine("3. " + T("Сменить язык", "Change language"));
            Console.WriteLine("4. " + T("Выйти", "Exit"));
            Console.Write(T("Выбор: ", "Choice: "));

            string choice = Console.ReadLine();

            if (choice == "1") AddService();
            else if (choice == "2") GetService();
            else if (choice == "3") ChooseLanguage();
            else if (choice == "4") break;
        }
    }
}
