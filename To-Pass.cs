using System;
using System.IO;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

class PasswordManager
{
    // ================= FILES =================
    static string configFile = "config.txt";
    static string userFilePath = "users/";

    static string masterKey = "MASTER-KEY-CHANGE-THIS";
    static string passwordKey = "PASSWORD-KEY-CHANGE-THIS";

    static Dictionary<string, string> vault = new Dictionary<string, string>();
    static string language = "RU";
    static string currentUser = "";

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

    // ================= USER MANAGEMENT =================

    static void CreateAccount()
    {
        Console.WriteLine("\n=== CREATE NEW USER ===");
        Console.WriteLine("Введите имя пользователя / Enter username:");

        string userName = Console.ReadLine() ?? "";

        if (string.IsNullOrEmpty(userName))
        {
            Console.WriteLine("Имя пользователя не может быть пустым!");
            return;
        }

        Console.WriteLine("Создайте мастер-пароль / Create master password:");
        string pass1 = ReadHidden();
        Console.WriteLine("Повторите пароль / Repeat password:");
        string pass2 = ReadHidden();

        if (pass1 != pass2 || pass1.Length < 4)
        {
            Console.WriteLine("Пароли не совпадают или слишком короткие!");
            return;
        }

        string hashed = Hash(pass1);
        string encryptedHash = EncryptAES(hashed, masterKey);

        // Create user folder and save encrypted master password
        string userPath = Path.Combine(userFilePath, userName);
        Directory.CreateDirectory(userPath);
        File.WriteAllText(Path.Combine(userPath, "master.cfg"), encryptedHash);

        Console.WriteLine("Пользователь создан и мастер-пароль сохранён!");
    }

    static bool Login()
    {
        Console.WriteLine("\n=== LOGIN ===");
        Console.WriteLine("Введите имя пользователя / Enter username:");
        string userName = Console.ReadLine() ?? "";

        string userPath = Path.Combine(userFilePath, userName);

        if (!Directory.Exists(userPath))
        {
            Console.WriteLine("Пользователь не найден!");
            return false;
        }

        Console.WriteLine("Введите мастер-пароль / Enter master password:");
        string inputPassword = ReadHidden();

        string encryptedHash = File.ReadAllText(Path.Combine(userPath, "master.cfg"));
        string storedHash = DecryptAES(encryptedHash, masterKey);

        if (Hash(inputPassword) == storedHash)
        {
            currentUser = userName;
            LoadVault();
            Console.WriteLine($"Вход в аккаунт {currentUser} успешен!");
            return true;
        }

        Console.WriteLine("Неверный мастер-пароль!");
        return false;
    }

    // ================= STORAGE =================

    static void LoadVault()
    {
        vault.Clear();
        string userPath = Path.Combine(userFilePath, currentUser);

        if (!Directory.Exists(userPath))
            return;

        string vaultFile = Path.Combine(userPath, "vault.txt");
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

    static void SaveVault()
    {
        string userPath = Path.Combine(userFilePath, currentUser);
        string vaultFile = Path.Combine(userPath, "vault.txt");

        StringBuilder data = new StringBuilder();

        foreach (var entry in vault)
        {
            data.AppendLine("SERVICE:" + entry.Key);
            data.AppendLine("PASSWORD:" + entry.Value);
            data.AppendLine("---");
        }

        File.WriteAllText(vaultFile, data.ToString());
    }

    // ================= PASSWORD =================

    static string GeneratePassword(int length, bool useCyrillic)
    {
        string latinChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+<>?";
        string cyrillicChars = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя" +
                                "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";

        string allChars = useCyrillic ? latinChars + cyrillicChars : latinChars;

        Random rnd = new Random();
        StringBuilder pass = new StringBuilder();

        for (int i = 0; i < length; i++)
            pass.Append(allChars[rnd.Next(allChars.Length)]);

        return pass.ToString();
    }

    // ================= GITHUB LINK =================

    static void ShowGitHubLink()
    {
        Console.WriteLine("\nGitHub Project: https://github.com/KoTTana24/To-Pass/");
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

        Console.Write(T("Использовать кириллицу? (y/n): ", "Use Cyrillic? (y/n): "));
        string choice = Console.ReadLine()?.ToLower() ?? "n";
        bool useCyrillic = choice == "y" || choice == "д";

        string password = GeneratePassword(length, useCyrillic);
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
        // Загружаем язык при запуске программы
        LoadLanguage();

        while (true)
        {
            Console.WriteLine("Менеджер паролей / Password Manager");
            Console.WriteLine("1. " + T("Создать аккаунт", "Create account"));
            Console.WriteLine("2. " + T("Войти в аккаунт", "Login"));
            Console.WriteLine("3. " + T("Выход", "Exit"));
            Console.Write(T("Выбор: ", "Choice: "));

            string choice = Console.ReadLine() ?? "";

            if (choice == "1")
                CreateAccount();
            else if (choice == "2")
            {
                if (Login())
                {
                    while (true)
                    {
                        Console.WriteLine("\n=== PASSWORD MANAGER ===");
                        Console.WriteLine("1. " + T("Добавить сервис", "Add service"));
                        Console.WriteLine("2. " + T("Получить пароль", "Get password"));
                        Console.WriteLine("3. " + T("Сменить язык", "Change language"));
                        Console.WriteLine("4. " + T("GitHub проект", "GitHub Project"));
                        Console.WriteLine("5. " + T("Выход из приложения", "Exit"));
                        Console.Write(T("Выбор: ", "Choice: "));

                        string subChoice = Console.ReadLine() ?? "";

                        if (subChoice == "1") AddService();
                        else if (subChoice == "2") GetService();
                        else if (subChoice == "3") ChooseLanguage();
                        else if (subChoice == "4") ShowGitHubLink();
                        else if (subChoice == "5") return;
                    }
                }
            }
            else if (choice == "3") return;
        }
    }
}
