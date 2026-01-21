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

    // ================= SETTINGS =================
    static int defaultPasswordLength = 12;
    static bool defaultUseCyrillic = false;
    static bool askBeforeShowPassword = true;

    // ================= CRYPTO CORE =================

    static byte[] GetKey(string key)
    {
        using SHA256 sha = SHA256.Create();
        return sha.ComputeHash(Encoding.UTF8.GetBytes(key));
    }

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
        Console.WriteLine("\n=== CREATE USER ===");
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

        string userPath = Path.Combine(userFilePath, userName);
        Directory.CreateDirectory(userPath);
        File.WriteAllText(Path.Combine(userPath, "master.cfg"), encryptedHash);

        Console.WriteLine("Пользователь создан!");
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
            LoadSettings();
            Console.WriteLine($"Вход выполнен: {currentUser}");
            return true;
        }

        Console.WriteLine("Неверный мастер-пароль!");
        return false;
    }

    // ================= STORAGE =================

    static void LoadVault()
    {
        vault.Clear();
        string vaultFile = Path.Combine(userFilePath, currentUser, "vault.txt");

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
        string vaultFile = Path.Combine(userFilePath, currentUser, "vault.txt");

        StringBuilder data = new StringBuilder();
        foreach (var entry in vault)
        {
            data.AppendLine("SERVICE:" + entry.Key);
            data.AppendLine("PASSWORD:" + entry.Value);
            data.AppendLine("---");
        }

        File.WriteAllText(vaultFile, data.ToString());
    }

    // ================= SETTINGS =================

    static void LoadSettings()
    {
        string settingsFile = Path.Combine(userFilePath, currentUser, "settings.cfg");

        if (!File.Exists(settingsFile))
            return;

        foreach (string line in File.ReadAllLines(settingsFile))
        {
            if (line.StartsWith("LENGTH="))
                int.TryParse(line.Replace("LENGTH=", ""), out defaultPasswordLength);
            else if (line.StartsWith("CYRILLIC="))
                defaultUseCyrillic = line.Replace("CYRILLIC=", "") == "1";
            else if (line.StartsWith("ASKSHOW="))
                askBeforeShowPassword = line.Replace("ASKSHOW=", "") == "1";
        }
    }

    static void SaveSettings()
    {
        string settingsFile = Path.Combine(userFilePath, currentUser, "settings.cfg");

        StringBuilder data = new StringBuilder();
        data.AppendLine("LENGTH=" + defaultPasswordLength);
        data.AppendLine("CYRILLIC=" + (defaultUseCyrillic ? "1" : "0"));
        data.AppendLine("ASKSHOW=" + (askBeforeShowPassword ? "1" : "0"));

        File.WriteAllText(settingsFile, data.ToString());
    }


//=========Settings Menu=========
    static void SettingsMenu()
{
    while (true)
    {
        Console.WriteLine("\n=== SETTINGS ===");
        Console.WriteLine($"1. {T("Длина пароля", "Password length")}: {defaultPasswordLength}");
        Console.WriteLine($"2. {T("Использовать кириллицу", "Use Cyrillic")}: {(defaultUseCyrillic ? "ON" : "OFF")}");
        Console.WriteLine($"3. {T("Спрашивать перед показом пароля", "Ask before showing password")}: {(askBeforeShowPassword ? "ON" : "OFF")}");
        Console.WriteLine($"4. {T("Язык", "Language")}: {(language == "RU" ? "Русский" : "English")}");
        Console.WriteLine("5. " + T("Назад", "Back"));
        Console.Write(T("Выбор: ", "Choice: "));

        string choice = Console.ReadLine() ?? "";

        if (choice == "1")
        {
            Console.Write(T("Введите длину: ", "Enter length: "));
            if (int.TryParse(Console.ReadLine(), out int len) && len >= 4)
            {
                defaultPasswordLength = len;
                SaveSettings();
            }
        }
        else if (choice == "2")
        {
            defaultUseCyrillic = !defaultUseCyrillic;
            SaveSettings();
        }
        else if (choice == "3")
        {
            askBeforeShowPassword = !askBeforeShowPassword;
            SaveSettings();
        }
        else if (choice == "4")
        {
            ChooseLanguage(); // ← вот тут смена языка
        }
        else if (choice == "5")
        {
            return;
        }
    }
}


    // ================= SMART SEARCH =================

    static int LevenshteinDistance(string s, string t)
    {
        int[,] dp = new int[s.Length + 1, t.Length + 1];

        for (int i = 0; i <= s.Length; i++)
            dp[i, 0] = i;
        for (int j = 0; j <= t.Length; j++)
            dp[0, j] = j;

        for (int i = 1; i <= s.Length; i++)
        {
            for (int j = 1; j <= t.Length; j++)
            {
                int cost = s[i - 1] == t[j - 1] ? 0 : 1;

                dp[i, j] = Math.Min(
                    Math.Min(dp[i - 1, j] + 1, dp[i, j - 1] + 1),
                    dp[i - 1, j - 1] + cost
                );
            }
        }

        return dp[s.Length, t.Length];
    }

    static string? FindClosestService(string input)
    {
        string? bestMatch = null;
        int bestScore = int.MaxValue;

        foreach (var service in vault.Keys)
        {
            int dist = LevenshteinDistance(input.ToLower(), service.ToLower());
            if (dist < bestScore)
            {
                bestScore = dist;
                bestMatch = service;
            }
        }

        return bestScore <= 3 ? bestMatch : null;
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

    // ================= FEATURES =================

    static void AddService()
    {
        Console.Write(T("Введите сервис: ", "Enter service: "));
        string service = Console.ReadLine() ?? "";

        string password = GeneratePassword(defaultPasswordLength, defaultUseCyrillic);
        vault[service] = EncryptAES(password, passwordKey);
        SaveVault();

        Console.WriteLine(T("\nПароль создан!", "\nPassword created!"));

        if (askBeforeShowPassword)
        {
            Console.Write(T("Показать пароль? (y/n): ", "Show password? (y/n): "));
            string c = Console.ReadLine()?.ToLower() ?? "n";
            if (c == "y" || c == "д")
                Console.WriteLine(T("Пароль: ", "Password: ") + password);
        }
        else
        {
            Console.WriteLine(T("Пароль: ", "Password: ") + password);
        }
    }

    static void ShowPasswordsList()
    {
        if (vault.Count == 0)
        {
            Console.WriteLine(T("Список пуст.", "List is empty."));
            return;
        }

        Console.WriteLine(T("\nВсе сервисы:", "\nAll services:"));
        foreach (var entry in vault)
        {
            Console.WriteLine($"{T("Сервис:", "Service:")} {entry.Key}");
        }
    }

    static void GetService()
    {
        Console.Write(T("Введите сервис: ", "Enter service: "));
        string input = Console.ReadLine() ?? "";

        string? service = vault.ContainsKey(input)
            ? input
            : FindClosestService(input);

        if (service == null)
        {
            Console.WriteLine(T("Сервис не найден!", "Service not found!"));
            return;
        }

        string password = DecryptAES(vault[service], passwordKey);

        if (askBeforeShowPassword)
        {
            Console.Write(T("Показать пароль? (y/n): ", "Show password? (y/n): "));
            string c = Console.ReadLine()?.ToLower() ?? "n";
            if (c == "y" || c == "д")
                Console.WriteLine(T("Пароль: ", "Password: ") + password);
        }
        else
        {
            Console.WriteLine(T("Пароль: ", "Password: ") + password);
        }
    }

    // ================= MAIN =================

    static void Main()
    {
        LoadLanguage();

        while (true)
        {
            Console.WriteLine("\n=== PASSWORD MANAGER ===");
            Console.WriteLine("1. " + T("Создать аккаунт", "Create account"));
            Console.WriteLine("2. " + T("Войти", "Login"));
            Console.WriteLine("3. " + T("Выход", "Exit"));
            Console.Write(T("Выбор: ", "Choice: "));

            string choice = Console.ReadLine() ?? "";

            if (choice == "1") CreateAccount();
            else if (choice == "2")
            {
                if (Login())
                {
                    while (true)
                    {
                        Console.WriteLine("\n=== 2PASS ===");
                        Console.WriteLine("1. " + T("Добавить сервис", "Add service"));
                        Console.WriteLine("2. " + T("Получить пароль (умный поиск)", "Get password (smart search)"));
                        Console.WriteLine("3. " + T("Список сервисов", "Service list"));
                        Console.WriteLine("4. " + T("Настройки", "Settings"));
                        Console.WriteLine("5. " + T("Выход", "Exit"));
                        Console.Write(T("Выбор: ", "Choice: "));

                        string sub = Console.ReadLine() ?? "";

                        if (sub == "1") AddService();
                        else if (sub == "2") GetService();
                        else if (sub == "3") ShowPasswordsList();
                        else if (sub == "4") SettingsMenu();
                        else if (sub == "5") return;
                    }
                }
            }
            else if (choice == "3") return;
        }
    }
}


