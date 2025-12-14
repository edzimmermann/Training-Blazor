# C#/.NET Cryptography Security: Detailed Guide with Examples

## 1. Using Weak Encryption Algorithms

### The Problem
Outdated algorithms like DES, 3DES, and RC4 have known vulnerabilities and can be broken with modern computing power.

### Wrong ❌
```csharp
public string EncryptData(string plaintext, string password)
{
    // DES is cryptographically broken!
    using (var des = new DESCryptoServiceProvider())
    {
        des.Key = Encoding.UTF8.GetBytes(password.Substring(0, 8));
        des.IV = new byte[8];
        
        using (var encryptor = des.CreateEncryptor())
        using (var ms = new MemoryStream())
        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        {
            byte[] data = Encoding.UTF8.GetBytes(plaintext);
            cs.Write(data, 0, data.Length);
            cs.FlushFinalBlock();
            return Convert.ToBase64String(ms.ToArray());
        }
    }
}

// Also weak: TripleDES, RC2
```

### Right ✅
```csharp
public string EncryptData(string plaintext, byte[] key, byte[] iv)
{
    // Use AES-256 (industry standard)
    using (var aes = Aes.Create())
    {
        aes.KeySize = 256;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = key; // 32 bytes for AES-256
        aes.IV = iv;   // 16 bytes
        
        using (var encryptor = aes.CreateEncryptor())
        using (var ms = new MemoryStream())
        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        {
            byte[] data = Encoding.UTF8.GetBytes(plaintext);
            cs.Write(data, 0, data.Length);
            cs.FlushFinalBlock();
            return Convert.ToBase64String(ms.ToArray());
        }
    }
}

// Best practice: Use AesGcm for authenticated encryption (.NET Core 3.0+)
public byte[] EncryptWithAuthentication(string plaintext, byte[] key)
{
    byte[] nonce = new byte[AesGcm.NonceByteSizes.MaxSize]; // 12 bytes
    byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];     // 16 bytes
    byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
    byte[] ciphertext = new byte[plaintextBytes.Length];
    
    using (var rng = RandomNumberGenerator.Create())
    {
        rng.GetBytes(nonce);
    }
    
    using (var aesGcm = new AesGcm(key))
    {
        aesGcm.Encrypt(nonce, plaintextBytes, ciphertext, tag);
    }
    
    // Combine nonce + tag + ciphertext for storage
    byte[] result = new byte[nonce.Length + tag.Length + ciphertext.Length];
    Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
    Buffer.BlockCopy(tag, 0, result, nonce.Length, tag.Length);
    Buffer.BlockCopy(ciphertext, 0, result, nonce.Length + tag.Length, ciphertext.Length);
    
    return result;
}
```

---

## 2. Hardcoded Encryption Keys

### The Problem
Hardcoded keys in source code are easily discovered and compromise all encrypted data.

### Wrong ❌
```csharp
public class DataEncryptor
{
    // Never do this!
    private static readonly byte[] Key = new byte[]
    {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
    
    public string Encrypt(string data)
    {
        return EncryptData(data, Key);
    }
}
```

### Right ✅
```csharp
// Option 1: Use Azure Key Vault (recommended for production)
public class SecureDataEncryptor
{
    private readonly SecretClient _keyVaultClient;
    
    public SecureDataEncryptor(string keyVaultUrl)
    {
        _keyVaultClient = new SecretClient(
            new Uri(keyVaultUrl),
            new DefaultAzureCredential()
        );
    }
    
    public async Task<string> EncryptAsync(string data)
    {
        KeyVaultSecret secret = await _keyVaultClient.GetSecretAsync("encryption-key");
        byte[] key = Convert.FromBase64String(secret.Value);
        
        byte[] iv = RandomNumberGenerator.GetBytes(16);
        return EncryptData(data, key, iv);
    }
}

// Option 2: Use Data Protection API (Windows/.NET)
public class DpapiEncryptor
{
    public string Encrypt(string data)
    {
        byte[] plaintext = Encoding.UTF8.GetBytes(data);
        
        byte[] ciphertext = ProtectedData.Protect(
            plaintext,
            null,
            DataProtectionScope.CurrentUser
        );
        
        return Convert.ToBase64String(ciphertext);
    }
    
    public string Decrypt(string encryptedData)
    {
        byte[] ciphertext = Convert.FromBase64String(encryptedData);
        
        byte[] plaintext = ProtectedData.Unprotect(
            ciphertext,
            null,
            DataProtectionScope.CurrentUser
        );
        
        return Encoding.UTF8.GetString(plaintext);
    }
}

// Option 3: Use ASP.NET Core Data Protection
public class DataProtectionEncryptor
{
    private readonly IDataProtector _protector;
    
    public DataProtectionEncryptor(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector("MyApp.DataEncryption");
    }
    
    public string Encrypt(string data)
    {
        return _protector.Protect(data);
    }
    
    public string Decrypt(string encryptedData)
    {
        return _protector.Unprotect(encryptedData);
    }
}

// Startup configuration
public void ConfigureServices(IServiceCollection services)
{
    services.AddDataProtection()
        .PersistKeysToFileSystem(new DirectoryInfo(@"\\server\share\keys"))
        .ProtectKeysWithCertificate("thumbprint");
}
```

---

## 3. Improper IV (Initialization Vector) Usage

### The Problem
Reusing IVs or using predictable IVs weakens encryption, potentially exposing patterns in encrypted data.

### Wrong ❌
```csharp
public string EncryptWithStaticIV(string plaintext, byte[] key)
{
    using (var aes = Aes.Create())
    {
        aes.Key = key;
        aes.IV = new byte[16]; // All zeros - NEVER DO THIS!
        
        using (var encryptor = aes.CreateEncryptor())
        using (var ms = new MemoryStream())
        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        {
            byte[] data = Encoding.UTF8.GetBytes(plaintext);
            cs.Write(data, 0, data.Length);
            cs.FlushFinalBlock();
            return Convert.ToBase64String(ms.ToArray());
        }
    }
}
```

### Right ✅
```csharp
public class SecureEncryption
{
    public string Encrypt(string plaintext, byte[] key)
    {
        // Generate random IV for each encryption
        byte[] iv = RandomNumberGenerator.GetBytes(16);
        
        byte[] ciphertext;
        using (var aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            
            using (var encryptor = aes.CreateEncryptor())
            using (var ms = new MemoryStream())
            using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            {
                byte[] data = Encoding.UTF8.GetBytes(plaintext);
                cs.Write(data, 0, data.Length);
                cs.FlushFinalBlock();
                ciphertext = ms.ToArray();
            }
        }
        
        // Prepend IV to ciphertext for storage/transmission
        byte[] result = new byte[iv.Length + ciphertext.Length];
        Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
        Buffer.BlockCopy(ciphertext, 0, result, iv.Length, ciphertext.Length);
        
        return Convert.ToBase64String(result);
    }
    
    public string Decrypt(string encryptedData, byte[] key)
    {
        byte[] fullCipher = Convert.FromBase64String(encryptedData);
        
        // Extract IV from the beginning
        byte[] iv = new byte[16];
        byte[] ciphertext = new byte[fullCipher.Length - 16];
        
        Buffer.BlockCopy(fullCipher, 0, iv, 0, 16);
        Buffer.BlockCopy(fullCipher, 16, ciphertext, 0, ciphertext.Length);
        
        using (var aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            
            using (var decryptor = aes.CreateDecryptor())
            using (var ms = new MemoryStream(ciphertext))
            using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
            using (var reader = new StreamReader(cs))
            {
                return reader.ReadToEnd();
            }
        }
    }
}
```

---

## 4. Using ECB Mode

### The Problem
ECB (Electronic Codebook) mode encrypts identical plaintext blocks to identical ciphertext blocks, revealing patterns.

### Wrong ❌
```csharp
public byte[] EncryptWithECB(byte[] data, byte[] key)
{
    using (var aes = Aes.Create())
    {
        aes.Key = key;
        aes.Mode = CipherMode.ECB; // Insecure!
        aes.Padding = PaddingMode.PKCS7;
        
        using (var encryptor = aes.CreateEncryptor())
        {
            return encryptor.TransformFinalBlock(data, 0, data.Length);
        }
    }
}
```

### Right ✅
```csharp
public byte[] EncryptSecurely(byte[] data, byte[] key)
{
    byte[] iv = RandomNumberGenerator.GetBytes(16);
    
    using (var aes = Aes.Create())
    {
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC; // Secure mode
        aes.Padding = PaddingMode.PKCS7;
        
        using (var encryptor = aes.CreateEncryptor())
        using (var ms = new MemoryStream())
        {
            ms.Write(iv, 0, iv.Length);
            
            byte[] encrypted = encryptor.TransformFinalBlock(data, 0, data.Length);
            ms.Write(encrypted, 0, encrypted.Length);
            
            return ms.ToArray();
        }
    }
}
```

---

## 5. Not Authenticating Encrypted Data

### The Problem
Without authentication (MAC/HMAC), attackers can modify ciphertext without detection.

### Wrong ❌
```csharp
public byte[] Encrypt(byte[] data, byte[] key)
{
    byte[] iv = RandomNumberGenerator.GetBytes(16);
    
    using (var aes = Aes.Create())
    {
        aes.Key = key;
        aes.IV = iv;
        
        using (var encryptor = aes.CreateEncryptor())
        using (var ms = new MemoryStream())
        {
            ms.Write(iv, 0, iv.Length);
            byte[] encrypted = encryptor.TransformFinalBlock(data, 0, data.Length);
            ms.Write(encrypted, 0, encrypted.Length);
            return ms.ToArray();
        }
    }
    // No MAC - attacker can modify ciphertext!
}
```

### Right ✅
```csharp
// Option 1: Use AES-GCM (authenticated encryption)
public class AuthenticatedEncryption
{
    public byte[] EncryptGCM(byte[] plaintext, byte[] key)
    {
        if (key.Length != 32)
            throw new ArgumentException("Key must be 256 bits");
        
        byte[] nonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
        byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];
        byte[] ciphertext = new byte[plaintext.Length];
        
        using (var aesGcm = new AesGcm(key))
        {
            aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);
        }
        
        byte[] result = new byte[nonce.Length + tag.Length + ciphertext.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
        Buffer.BlockCopy(tag, 0, result, nonce.Length, tag.Length);
        Buffer.BlockCopy(ciphertext, 0, result, nonce.Length + tag.Length, ciphertext.Length);
        
        return result;
    }
    
    public byte[] DecryptGCM(byte[] encryptedData, byte[] key)
    {
        byte[] nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
        byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];
        byte[] ciphertext = new byte[encryptedData.Length - nonce.Length - tag.Length];
        
        Buffer.BlockCopy(encryptedData, 0, nonce, 0, nonce.Length);
        Buffer.BlockCopy(encryptedData, nonce.Length, tag, 0, tag.Length);
        Buffer.BlockCopy(encryptedData, nonce.Length + tag.Length, ciphertext, 0, ciphertext.Length);
        
        byte[] plaintext = new byte[ciphertext.Length];
        
        using (var aesGcm = new AesGcm(key))
        {
            aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
        }
        
        return plaintext;
    }
}

// Option 2: Encrypt-then-MAC with HMAC
public class EncryptThenMAC
{
    public byte[] Encrypt(byte[] plaintext, byte[] encryptionKey, byte[] macKey)
    {
        byte[] iv = RandomNumberGenerator.GetBytes(16);
        
        byte[] ciphertext;
        using (var aes = Aes.Create())
        {
            aes.Key = encryptionKey;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            
            using (var encryptor = aes.CreateEncryptor())
            {
                ciphertext = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
            }
        }
        
        byte[] dataToMac = new byte[iv.Length + ciphertext.Length];
        Buffer.BlockCopy(iv, 0, dataToMac, 0, iv.Length);
        Buffer.BlockCopy(ciphertext, 0, dataToMac, iv.Length, ciphertext.Length);
        
        byte[] mac;
        using (var hmac = new HMACSHA256(macKey))
        {
            mac = hmac.ComputeHash(dataToMac);
        }
        
        byte[] result = new byte[iv.Length + ciphertext.Length + mac.Length];
        Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
        Buffer.BlockCopy(ciphertext, 0, result, iv.Length, ciphertext.Length);
        Buffer.BlockCopy(mac, 0, result, iv.Length + ciphertext.Length, mac.Length);
        
        return result;
    }
    
    public byte[] Decrypt(byte[] encryptedData, byte[] encryptionKey, byte[] macKey)
    {
        int macLength = 32;
        byte[] iv = new byte[16];
        byte[] ciphertext = new byte[encryptedData.Length - 16 - macLength];
        byte[] receivedMac = new byte[macLength];
        
        Buffer.BlockCopy(encryptedData, 0, iv, 0, 16);
        Buffer.BlockCopy(encryptedData, 16, ciphertext, 0, ciphertext.Length);
        Buffer.BlockCopy(encryptedData, 16 + ciphertext.Length, receivedMac, 0, macLength);
        
        byte[] dataToMac = new byte[16 + ciphertext.Length];
        Buffer.BlockCopy(iv, 0, dataToMac, 0, 16);
        Buffer.BlockCopy(ciphertext, 0, dataToMac, 16, ciphertext.Length);
        
        byte[] computedMac;
        using (var hmac = new HMACSHA256(macKey))
        {
            computedMac = hmac.ComputeHash(dataToMac);
        }
        
        if (!CryptographicOperations.FixedTimeEquals(computedMac, receivedMac))
        {
            throw new CryptographicException("MAC verification failed!");
        }
        
        using (var aes = Aes.Create())
        {
            aes.Key = encryptionKey;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            
            using (var decryptor = aes.CreateDecryptor())
            {
                return decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
            }
        }
    }
}
```

---

## 6. Using Random Instead of Cryptographic RNG

### The Problem
`System.Random` is predictable and not suitable for generating cryptographic keys, IVs, or salts.

### Wrong ❌
```csharp
public byte[] GenerateKey()
{
    var random = new Random();
    byte[] key = new byte[32];
    random.NextBytes(key); // Predictable!
    return key;
}
```

### Right ✅
```csharp
public byte[] GenerateKey()
{
    return RandomNumberGenerator.GetBytes(32);
}

public byte[] GenerateSalt(int length = 32)
{
    return RandomNumberGenerator.GetBytes(length);
}

public string GenerateToken(int length = 32)
{
    byte[] randomBytes = RandomNumberGenerator.GetBytes(length);
    return Convert.ToBase64String(randomBytes)
        .Replace("+", "")
        .Replace("/", "")
        .Replace("=", "")
        .Substring(0, length);
}
```

---

## 7. Weak Password Hashing

### The Problem
Using fast hashing algorithms (MD5, SHA-256) for passwords makes them vulnerable to brute force.

### Wrong ❌
```csharp
public string HashPassword(string password)
{
    using (var md5 = MD5.Create())
    {
        byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(password));
        return Convert.ToBase64String(hash);
    }
}
```

### Right ✅
```csharp
// Option 1: ASP.NET Core Identity PasswordHasher
public class SecurePasswordService
{
    private readonly PasswordHasher<string> _hasher = new PasswordHasher<string>();
    
    public string HashPassword(string password)
    {
        return _hasher.HashPassword(null, password);
    }
    
    public bool VerifyPassword(string password, string hashedPassword)
    {
        var result = _hasher.VerifyHashedPassword(null, hashedPassword, password);
        return result == PasswordVerificationResult.Success;
    }
}

// Option 2: Manual PBKDF2
public class PBKDF2PasswordHasher
{
    private const int SaltSize = 32;
    private const int HashSize = 32;
    private const int Iterations = 100000;
    
    public string HashPassword(string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
        
        using (var pbkdf2 = new Rfc2898DeriveBytes(
            password, salt, Iterations, HashAlgorithmName.SHA256))
        {
            byte[] hash = pbkdf2.GetBytes(HashSize);
            
            byte[] hashBytes = new byte[SaltSize + HashSize];
            Buffer.BlockCopy(salt, 0, hashBytes, 0, SaltSize);
            Buffer.BlockCopy(hash, 0, hashBytes, SaltSize, HashSize);
            
            return Convert.ToBase64String(hashBytes);
        }
    }
    
    public bool VerifyPassword(string password, string hashedPassword)
    {
        byte[] hashBytes = Convert.FromBase64String(hashedPassword);
        
        byte[] salt = new byte[SaltSize];
        Buffer.BlockCopy(hashBytes, 0, salt, 0, SaltSize);
        
        byte[] storedHash = new byte[HashSize];
        Buffer.BlockCopy(hashBytes, SaltSize, storedHash, 0, HashSize);
        
        using (var pbkdf2 = new Rfc2898DeriveBytes(
            password, salt, Iterations, HashAlgorithmName.SHA256))
        {
            byte[] computedHash = pbkdf2.GetBytes(HashSize);
            return CryptographicOperations.FixedTimeEquals(computedHash, storedHash);
        }
    }
}
```

---

## Best Practices Summary

### Always Do:
1. **Use AES-256** with CBC or GCM mode
2. **Generate random IVs** for each encryption
3. **Use authenticated encryption** (GCM or Encrypt-then-MAC)
4. **Use RandomNumberGenerator** for crypto operations
5. **Use PBKDF2, bcrypt, or Argon2** for passwords
6. **Store keys securely** (Key Vault, not in code)
7. **Clear sensitive data** from memory
8. **Use constant-time comparisons** for secrets

### Never Do:
1. **Never use ECB mode**
2. **Never reuse IVs**
3. **Never hardcode keys**
4. **Never use MD5/SHA-1** for passwords
5. **Never use System.Random** for crypto
6. **Never store keys with encrypted data**

