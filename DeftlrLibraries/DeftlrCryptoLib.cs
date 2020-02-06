/*
 * Copyright (c) 2020 U&A Services UG
 */
using DeftlrLibraries;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;

public class SearchItemResponse
{
    // IV used for encryption/decryption of the SID and the content
    public string IV { get; set; }
    // Salt used for encryption/decryption of the SID and the content
    public string Salt { get; set; }
    // SecureID used to check the TAG and TOKEN combination/integrity (e.g. encrypted TAG and ID, used for round-trip security check)
    public string SID { get; set; }
    // <c>True</c> if the response is empty; <c>false</c> otherwise
    public bool IsEmpty { get; set; }
}

public class SearchItemMasterResponse
{
    public string Tag { get; set; }
    public DateTime CreationDate { get; set; }
    public string FileMimeType { get; set; }
}

public class ReadItemResponse
{
    // IV used for encryption/decryption of the SID and the content
    public string IV { get; set; }
    // Salt used for encryption/decryption of the SID and the content
    public string Salt { get; set; }
    // Encrypted message content
    public string Content { get; set; }
    // The file name in case the item is an encrypted file
    public string FileName { get; set; }
    // The file mime type in case the item is an encrypted file
    public string FileMimeType { get; set; }
    // The timestamp of the item creation
    public DateTime CreationDate { get; set; }
    // checks if the item contains any usable data
    public bool IsEmpty
    {
        get { return !(IV.IsNotNullOrEmpty() && Salt.IsNotNullOrEmpty() && Content.IsNotNullOrEmpty()); }
    }
    // checks if the item holds an image instead of text
    public bool IsImage
    {
        get { return FileName.IsNotNullOrEmpty() && FileMimeType.IsNotNullOrEmpty(); }
    }
}

public class CreateItem
{
    [JsonProperty(PropertyName = "id")]
    public string Id { get; set; }
    public string Tag { get; set; }
    public string IV { get; set; }
    public string Salt { get; set; }
    public string SID { get; set; }
    public string Content { get; set; }
    public string MasterTag { get; set; }
    public bool IsNotDeletable { get; set; }
    public string FileName { get; set; }
    public string FileMimeType { get; set; }
}

public class ServiceItem
{
    // Decrypted message content
    public string Content { get; set; }
    // Decrypted file content if the item represents a file
    public Byte[] ImageContent { get; set; }
    // The file name in case the item is an encrypted file
    public string FileName { get; set; }
    // The file mime type in case the item is an encrypted file
    public string FileMimeType { get; set; }
    // checks if the item contains any usable data
    public bool IsEmpty
    {
        get { return !(Content.IsNotNullOrEmpty() || (ImageContent.IsNotNull() && ImageContent.Length > 0)); }
    }
    // checks if the item holds an image instead of text
    public bool IsImage
    {
        get { return FileName.IsNotNullOrEmpty() && FileMimeType.IsNotNullOrEmpty() && (ImageContent.Length > 0); }
    }
}

public class DeftlrCryptoLib
{
    private string apiBaseAddress = @"https://deftlr.com/api/";

    private DeftlrCryptoHelper cryptoService = new DeftlrCryptoHelper();

    private string guid(int length = 32)
    {
        var l = ((length <= 0) || (length > 32)) ? 32 : length;
        return Guid.NewGuid().ToString().Replace("-", String.Empty).Substring(0, l);
    }

    public string ClientVerificationToken { get; private set; }

    public DeftlrCryptoLib(string clientVerificationToken)
    {
        this.ClientVerificationToken = clientVerificationToken;
    }

    public ReadItemResponse Read(string id)
    {
        ReadItemResponse serviceItem = null;
        apiBaseAddress
        .Append(@"read/{0}")
        .FormatWith(id)
        .DownloadString(this.ClientVerificationToken, response => serviceItem = response.DeserializeTo<ReadItemResponse>());
        return serviceItem;
    }

    public SearchItemResponse Search(string tag)
    {
        SearchItemResponse searchItem = null;
        apiBaseAddress
        .Append(@"search/{0}")
        .FormatWith(tag)
        .DownloadString(this.ClientVerificationToken, response => searchItem = response.DeserializeTo<SearchItemResponse>());
        return searchItem;
    }

    public string Id()
    {
        string id = String.Empty;
        apiBaseAddress
        .Append(@"id")
        .DownloadString(this.ClientVerificationToken, response => id = response.DeserializeTo<string>());
        return id;
    }

    public ServiceItem SearchAndRead(string tag, string token)
    {
        ServiceItem item = new ServiceItem();

        var searchItem = this.Search(tag);
        if (!searchItem.IsEmpty)
        {
            var messageId = Decrypt(token, searchItem.IV, searchItem.Salt, searchItem.SID);
            var readItem = this.Read(messageId);
            if (!readItem.IsEmpty)
            {
                if (readItem.IsImage)
                {
                    var resultBytes = DecryptImage(token, readItem.IV, readItem.Salt, readItem.Content);
                    item.ImageContent = resultBytes;
                    item.FileName = readItem.FileName;
                    item.FileMimeType = readItem.FileMimeType;
                }
                else
                {
                    var message = Decrypt(token, readItem.IV, readItem.Salt, readItem.Content);
                    item.Content = message;
                }
            }
        }
        return item;
    }

    public void Delete(string tag, string token)
    {
        var searchItem = this.Search(tag);
        if (!searchItem.IsEmpty)
        {
            var messageId = Decrypt(token, searchItem.IV, searchItem.Salt, searchItem.SID);
            apiBaseAddress
            .Append(@"delete/{0}")
            .FormatWith(messageId)
            .DeleteRequest(this.ClientVerificationToken, response => Console.WriteLine(response));
        }

    }

    public List<SearchItemMasterResponse> Master(string masterTag)
    {
        var searchItems = new List<SearchItemMasterResponse>();
        apiBaseAddress
        .Append(@"master/{0}")
        .FormatWith(masterTag)
        .DownloadString(this.ClientVerificationToken, response => searchItems = response.DeserializeTo<List<SearchItemMasterResponse>>());
        return searchItems;
    }

    private void prepareForCreate(string tag, string token, Func<CreateItem, Func<string, string>, CreateItem> fill)
    {
        var searchItem = Search(tag);
        if (searchItem.IsEmpty)
        {
            var iv = guid(16).GetBytes().ToBase64();
            var salt = guid().ToBase64();

            var encryptor = new DeftlrCryptoHelper(token, iv, salt);

            var newId = Id();
            var sId = encryptor.Encrypt(newId);
            var item = createItem(tag, newId, sId, iv, salt);

            apiBaseAddress
            .Append(@"create")
            .PostRequest(this.ClientVerificationToken, fill(item, chunk => encryptor.Encrypt(chunk)).ConvertToJson(), response => response.Print());
        }
        else
        {
            "Tag already exists".Print();
        }
    }

    private CreateItem createItem(string tag, string id, string sId, string iv, string salt)
    {
        var createItem = new CreateItem();

        createItem.Id = id;
        createItem.SID = sId;
        createItem.Tag = tag;
        createItem.IV = iv;
        createItem.Salt = salt;

        return createItem;
    }

    public void Create(string tag, string token, string message)
    {
        prepareForCreate(tag, token, (createItem, encryptor) =>
        {
            createItem.Content = encryptor(message);
            return createItem;
        });
    }

    public void Create(string tag, string token, FileInfo file)
    {
        if (file.Exists)
        {
            prepareForCreate(tag, token, (createItem, encryptor) =>
            {
                createItem.Content = file.FullName.ChunkifyContent(chunk => encryptor(chunk));
                createItem.FileName = file.Name;
                createItem.FileMimeType = file.Extension.GetFileMimeType();
                return createItem;
            });
        }
        else
        {
            Console.WriteLine("File does not exist!");
        }
    }

    public string Decrypt(string token, string iv, string salt, string encryptedText)
    {
        return cryptoService
                .Init(token, iv, salt)
                .Decrypt(encryptedText);
    }

    public Byte[] DecryptImage(string token, string iv, string salt, string encryptedImageContent)
    {
        var imageBytes = new List<byte>();
        cryptoService.Init(token, iv, salt);
        encryptedImageContent
            .Split(new string[] { "|" }, StringSplitOptions.None)
            .ToList()
            .ForEach(chunk => imageBytes.AddRange(Convert.FromBase64String(cryptoService.Decrypt(chunk))));
        return imageBytes.ToArray();
    }
}

public class DeftlrCryptoHelper
{
    private const int iterations = 1000;
    private const int blockSize = 128;
    private const int keySize = 128;

    private RijndaelManaged rijndaelManaged = null;
    private byte[] salt;

    public DeftlrCryptoHelper()
    {
    }

    public DeftlrCryptoHelper(string secret, string iv, string sa)
    {
        this.Init(secret, iv, sa);
    }

    public DeftlrCryptoHelper Init(string secret, string iv, string sa)
    {
        rijndaelManaged = new RijndaelManaged();
        rijndaelManaged.BlockSize = blockSize;
        rijndaelManaged.KeySize = keySize;
        rijndaelManaged.IV = HexStringToByteArray(iv.ToHexString());

        rijndaelManaged.Padding = PaddingMode.PKCS7;
        rijndaelManaged.Mode = CipherMode.CBC;
        salt = HexStringToByteArray(sa.ToHexString());
        rijndaelManaged.Key = generateKey(secret);

        return this;
    }

    public string Encrypt(string strPlainText)
    {
        byte[] strText = new System.Text.UTF8Encoding().GetBytes(strPlainText);
        ICryptoTransform transform = rijndaelManaged.CreateEncryptor();
        byte[] cipherText = transform.TransformFinalBlock(strText, 0, strText.Length);
        return Convert.ToBase64String(cipherText);
    }

    public string Decrypt(string encryptedText)
    {
        var encryptedBytes = Convert.FromBase64String(encryptedText);
        ICryptoTransform transform = rijndaelManaged.CreateDecryptor();
        byte[] cipherText = transform.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
        return System.Text.Encoding.UTF8.GetString(cipherText);
    }

    public static byte[] HexStringToByteArray(string strHex)
    {
        dynamic r = new byte[strHex.Length / 2];
        for (int i = 0; i <= strHex.Length - 1; i += 2)
        {
            r[i / 2] = Convert.ToByte(Convert.ToInt32(strHex.Substring(i, 2), 16));
        }
        return r;
    }

    private byte[] generateKey(string secret)
    {
        Rfc2898DeriveBytes rfc2898 = new Rfc2898DeriveBytes(System.Text.Encoding.UTF8.GetBytes(secret), salt, iterations);
        return rfc2898.GetBytes(keySize / 8);
    }
}

public static class ObjectExtentions
{
    public static bool IsNotNull(this object o)
    {
        return o != null;
    }

    public static bool IsOfType<T>(this object o)
    {
        return o is T;
    }

    public static T ConvertToType<T>(this object o)
    {
        return (T)Convert.ChangeType(o, typeof(T));
    }
}

public static class ProjectExtensions
{
    public static byte[] GetBytes(this string source)
    {
        return System.Text.Encoding.UTF8.GetBytes(source);
    }

    public static string ToHexString(this string base64)
    {
        var bytes = Convert.FromBase64String(base64);
        return BitConverter.ToString(bytes).Replace("-", String.Empty);
    }

    public static string ToBase64(this string source)
    {
        return ToBase64(GetBytes(source));
    }

    public static string ToBase64(this byte[] bytes)
    {
        return Convert.ToBase64String(bytes);
    }

    public static bool IsNotNullOrEmpty(this string source)
    {
        return !String.IsNullOrWhiteSpace(source);
    }

    public static T DeserializeTo<T>(this string json)
    {
        return JsonConvert.DeserializeObject<T>(json);
    }

    public static string ConvertToJson<T>(this T o)
    {
        return JsonConvert.SerializeObject(o);
    }

    public static string Append(this string source, params string[] parameters)
    {
        return Path.Combine(new List<string> { source }.ToArray().Concat(parameters).ToArray());
    }

    public static string FormatWith(this string source, params string[] parameters)
    {
        return String.Format(source, parameters);
    }

    public static void DownloadString(this string url, string clientVerificationToken, Action<string> action)
    {
        using (var webClient = new WebClient())
        {
            webClient.Headers.Add(HttpRequestHeader.UserAgent, "DeftlrCryptoLib");
            webClient.Headers.Add("ClientVerificationToken", clientVerificationToken);
            var response = webClient.DownloadString(url);
            action(response);
        }
    }

    public static void DeleteRequest(this string url, string clientVerificationToken, Action<string> action)
    {
        using (var webClient = new WebClient())
        {
            webClient.Headers.Add(HttpRequestHeader.UserAgent, "DeftlrCryptoLib");
            webClient.Headers.Add("ClientVerificationToken", clientVerificationToken);
            var response = webClient.UploadString(url, "DELETE", String.Empty);
            action(response);
        }
    }

    public static void PostRequest(this string url, string clientVerificationToken, string serviceItemAsJson, Action<string> action)
    {
        using (var webClient = new WebClient())
        {
            webClient.Headers.Add(HttpRequestHeader.UserAgent, "DeftlrCryptoLib");
            webClient.Headers.Add("ClientVerificationToken", clientVerificationToken);
            webClient.Headers.Add("content-type", "application/json");
            var response = webClient.UploadString(url, "POST", serviceItemAsJson);
            action(response);
        }
    }

    public static string GetFileMimeType(this string extension)
    {
        var map = new Dictionary<string, string>();
        map.Add(".png", "image/png");
        map.Add(".jpg", "image/jpeg");
        map.Add(".jpeg", "image/jpeg");
        map.Add(".bmp", "image/bmp");
        map.Add(".gif", "image/gif");
        map.Add(".zip", "application/zip");
        map.Add(".mpeg", "video/mpeg");
        map.Add(".mp3", "audio/mpeg3");
        map.Add(".txt", "text/plain");
        map.Add(".xml", "text/xml");
        map.Add(".html", "text/html");
        map.Add(".pdf", "application/pdf");

        return map.ContainsKey(extension) ? map[extension] : "text/plain";
    }

    public static string ChunkifyContent(this string fileName, Func<string, string> encryptor)
    {
        var delimiter = "|";
        var chunkSize = 1024;
        var chunks = new StringBuilder();
        var fileContentBytes = File.ReadAllBytes(fileName);
        for (var i = 0; i < fileContentBytes.Length; i += chunkSize)
        {
            var chunk = encryptor(fileContentBytes.Skip(i).Take(chunkSize).ToArray().ToBase64());
            chunks.Append(chunk);
            chunks.Append(delimiter);
        }
        chunks.Remove(chunks.Length - 1, 1); // remove last delimiter character
        return chunks.ToString();
    }
}