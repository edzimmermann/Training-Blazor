# C#/.NET Code Quality & Logic Security: Detailed Guide with Examples

## 1. Race Conditions in Concurrent Code

### The Problem
Race conditions occur when multiple threads access shared resources without proper synchronization, leading to unpredictable behavior and security vulnerabilities.

### Wrong ❌
```csharp
public class BankAccount
{
    private decimal balance = 1000m;
    
    public void Withdraw(decimal amount)
    {
        if (balance >= amount)
        {
            // Another thread could modify balance here!
            Thread.Sleep(10); // Simulating processing time
            balance -= amount;
        }
    }
}
```

### Right ✅
```csharp
public class BankAccount
{
    private decimal balance = 1000m;
    private readonly object balanceLock = new object();
    
    public void Withdraw(decimal amount)
    {
        lock (balanceLock)
        {
            if (balance >= amount)
            {
                balance -= amount;
            }
        }
    }
}
```

---

## 2. Not Disposing IDisposable Resources

### The Problem
Failing to dispose resources can lead to memory leaks, file locks, database connection exhaustion, and denial of service.

### Wrong ❌
```csharp
public void ProcessFile(string path)
{
    var stream = new FileStream(path, FileMode.Open);
    var reader = new StreamReader(stream);
    var content = reader.ReadToEnd();
    // Stream and reader never disposed - file remains locked!
    ProcessContent(content);
}
```

### Right ✅
```csharp
public void ProcessFile(string path)
{
    using (var stream = new FileStream(path, FileMode.Open))
    using (var reader = new StreamReader(stream))
    {
        var content = reader.ReadToEnd();
        ProcessContent(content);
    }
    // Resources automatically disposed
}

// Or with C# 8.0+ using declarations:
public void ProcessFile(string path)
{
    using var stream = new FileStream(path, FileMode.Open);
    using var reader = new StreamReader(stream);
    var content = reader.ReadToEnd();
    ProcessContent(content);
}
```

---

## 3. Integer Overflow Without Checks

### The Problem
Integer overflow can bypass security checks, corrupt data, or cause unexpected behavior in calculations involving money, permissions, or array indices.

### Wrong ❌
```csharp
public void AllocateBuffer(int size, int multiplier)
{
    int totalSize = size * multiplier; // Can overflow!
    byte[] buffer = new byte[totalSize]; // May allocate tiny buffer or throw
}

public bool HasPermission(int userLevel, int requiredLevel)
{
    int permissionScore = userLevel * 1000; // Can overflow to negative!
    return permissionScore >= requiredLevel;
}
```

### Right ✅
```csharp
public void AllocateBuffer(int size, int multiplier)
{
    checked
    {
        int totalSize = size * multiplier; // Throws on overflow
        byte[] buffer = new byte[totalSize];
    }
}

public bool HasPermission(int userLevel, int requiredLevel)
{
    // Validate before calculation
    if (userLevel < 0 || requiredLevel < 0) return false;
    if (userLevel > int.MaxValue / 1000) return false; // Prevent overflow
    
    int permissionScore = userLevel * 1000;
    return permissionScore >= requiredLevel;
}

// Or enable checked arithmetic globally in project settings
```

---

## 4. Path Traversal Vulnerabilities

### The Problem
Failing to validate file paths allows attackers to access files outside intended directories using sequences like `../` or absolute paths.

### Wrong ❌
```csharp
public string ReadUserFile(string fileName)
{
    string basePath = @"C:\UserFiles\";
    string fullPath = basePath + fileName; // Dangerous!
    return File.ReadAllText(fullPath);
}
// Attacker sends: "..\..\Windows\System32\config\SAM"
```

### Right ✅
```csharp
public string ReadUserFile(string fileName)
{
    string basePath = @"C:\UserFiles\";
    
    // Validate filename doesn't contain path traversal
    if (fileName.Contains("..") || Path.IsPathRooted(fileName))
    {
        throw new SecurityException("Invalid file name");
    }
    
    // Use Path.Combine and GetFullPath
    string fullPath = Path.GetFullPath(Path.Combine(basePath, fileName));
    
    // Verify the resolved path is still within base directory
    if (!fullPath.StartsWith(basePath, StringComparison.OrdinalIgnoreCase))
    {
        throw new SecurityException("Path traversal detected");
    }
    
    return File.ReadAllText(fullPath);
}
```

---

## 5. Command Injection Through Process.Start()

### The Problem
Passing unsanitized user input to system commands allows attackers to execute arbitrary commands.

### Wrong ❌
```csharp
public void ConvertImage(string inputFile, string outputFile)
{
    var process = new Process
    {
        StartInfo = new ProcessStartInfo
        {
            FileName = "convert",
            Arguments = $"{inputFile} {outputFile}", // Injection risk!
            UseShellExecute = true
        }
    };
    process.Start();
}
// Attacker sends: "input.jpg & del /F /Q C:\*.*"
```

### Right ✅
```csharp
public void ConvertImage(string inputFile, string outputFile)
{
    // Validate inputs
    if (!File.Exists(inputFile))
        throw new FileNotFoundException("Input file not found");
    
    // Whitelist allowed characters
    if (!IsValidFileName(inputFile) || !IsValidFileName(outputFile))
        throw new ArgumentException("Invalid file name");
    
    var process = new Process
    {
        StartInfo = new ProcessStartInfo
        {
            FileName = @"C:\Tools\convert.exe", // Use full path
            UseShellExecute = false, // Don't use shell
            CreateNoWindow = true,
            RedirectStandardOutput = true
        }
    };
    
    // Add arguments separately - they're automatically escaped
    process.StartInfo.ArgumentList.Add(inputFile);
    process.StartInfo.ArgumentList.Add(outputFile);
    
    process.Start();
}

private bool IsValidFileName(string fileName)
{
    return !string.IsNullOrWhiteSpace(fileName) &&
           fileName.IndexOfAny(Path.GetInvalidFileNameChars()) < 0 &&
           !fileName.Contains("..") &&
           Path.GetFileName(fileName) == fileName;
}
```

---

## 6. LDAP Injection

### The Problem
Concatenating user input into LDAP queries allows attackers to modify query logic and access unauthorized data.

### Wrong ❌
```csharp
public bool AuthenticateUser(string username, string password)
{
    string ldapPath = "LDAP://DC=example,DC=com";
    string filter = $"(&(uid={username})(userPassword={password}))";
    
    DirectoryEntry entry = new DirectoryEntry(ldapPath);
    DirectorySearcher searcher = new DirectorySearcher(entry)
    {
        Filter = filter // Injection vulnerable!
    };
    
    SearchResult result = searcher.FindOne();
    return result != null;
}
// Attacker sends username: "*)(uid=*))(|(uid=*"
// Resulting filter: "(&(uid=*)(uid=*))(|(uid=*)(userPassword=...))"
```

### Right ✅
```csharp
public bool AuthenticateUser(string username, string password)
{
    string ldapPath = "LDAP://DC=example,DC=com";
    
    // Escape special LDAP characters
    string escapedUsername = EscapeLdapSearchFilter(username);
    string escapedPassword = EscapeLdapSearchFilter(password);
    
    string filter = $"(&(uid={escapedUsername})(userPassword={escapedPassword}))";
    
    using (DirectoryEntry entry = new DirectoryEntry(ldapPath))
    using (DirectorySearcher searcher = new DirectorySearcher(entry))
    {
        searcher.Filter = filter;
        SearchResult result = searcher.FindOne();
        return result != null;
    }
}

private string EscapeLdapSearchFilter(string input)
{
    if (string.IsNullOrEmpty(input)) return input;
    
    return input
        .Replace(@"\", @"\5c")
        .Replace("*", @"\2a")
        .Replace("(", @"\28")
        .Replace(")", @"\29")
        .Replace("\0", @"\00");
}
```

---

## 7. Dynamic Code Execution

### The Problem
Using eval-like functionality or compiling user input as code creates severe remote code execution vulnerabilities.

### Wrong ❌
```csharp
public object EvaluateExpression(string expression)
{
    // Extremely dangerous!
    var script = CSharpScript.EvaluateAsync(expression).Result;
    return script;
}
// Attacker sends: "System.IO.File.Delete(@\"C:\important.txt\")"
```

### Right ✅
```csharp
public double EvaluateExpression(string expression)
{
    // Use a safe expression evaluator library or build a parser
    // Example: Allow only mathematical operations
    
    // Whitelist allowed characters
    if (!Regex.IsMatch(expression, @"^[0-9+\-*/().\s]+$"))
    {
        throw new ArgumentException("Invalid expression");
    }
    
    try
    {
        // Use a safe math parser library like NCalc with restrictions
        var expr = new NCalc.Expression(expression);
        
        // Disable functions and parameters
        expr.EvaluateFunction += (name, args) =>
        {
            throw new SecurityException("Functions not allowed");
        };
        
        return Convert.ToDouble(expr.Evaluate());
    }
    catch
    {
        throw new ArgumentException("Failed to evaluate expression");
    }
}
```

---

## 8. Improper Exception Handling

### The Problem
Catching all exceptions without proper handling can hide security issues, expose sensitive information, or leave the application in an insecure state.

### Wrong ❌
```csharp
public void ProcessPayment(PaymentInfo payment)
{
    try
    {
        ValidatePayment(payment);
        ChargeCard(payment);
        SendConfirmation(payment);
    }
    catch (Exception ex)
    {
        // Swallowing exception - payment may be in unknown state!
        Console.WriteLine(ex.ToString()); // Logs full stack trace
    }
}
```

### Right ✅
```csharp
public void ProcessPayment(PaymentInfo payment)
{
    try
    {
        ValidatePayment(payment);
        ChargeCard(payment);
        SendConfirmation(payment);
    }
    catch (PaymentValidationException ex)
    {
        // Handle specific expected exceptions
        LogSecurityEvent("Invalid payment attempt", payment.UserId);
        throw; // Re-throw to caller
    }
    catch (PaymentProcessingException ex)
    {
        // Handle payment failures
        LogError("Payment processing failed", ex.Message); // Don't log stack trace
        RollbackTransaction(payment);
        throw new UserFriendlyException("Payment failed. Please try again.");
    }
    // Don't catch generic Exception unless you re-throw
}

private void LogError(string message, string detail)
{
    // Log only safe information, not full exception details
    logger.Error($"{message}: {detail}");
}
```

---

## 9. Insufficient Logging for Security Events

### The Problem
Not logging security-relevant events makes it impossible to detect attacks, investigate breaches, or maintain audit trails.

### Wrong ❌
```csharp
public bool Login(string username, string password)
{
    var user = _userRepository.GetByUsername(username);
    
    if (user == null || !VerifyPassword(password, user.PasswordHash))
    {
        return false; // No logging!
    }
    
    CreateSession(user);
    return true;
}
```

### Right ✅
```csharp
public bool Login(string username, string password)
{
    // Log the attempt (but not the password!)
    _securityLogger.LogInformation(
        "Login attempt for user: {Username} from IP: {IpAddress}", 
        username, 
        GetClientIpAddress()
    );
    
    var user = _userRepository.GetByUsername(username);
    
    if (user == null)
    {
        _securityLogger.LogWarning(
            "Login failed - user not found: {Username} from IP: {IpAddress}",
            username,
            GetClientIpAddress()
        );
        // Still check password to prevent timing attacks
        VerifyPassword(password, GenerateDummyHash());
        return false;
    }
    
    if (!VerifyPassword(password, user.PasswordHash))
    {
        _securityLogger.LogWarning(
            "Login failed - invalid password for user: {Username} from IP: {IpAddress}",
            username,
            GetClientIpAddress()
        );
        
        // Track failed attempts
        IncrementFailedLoginAttempts(user);
        
        return false;
    }
    
    // Log successful login
    _securityLogger.LogInformation(
        "Successful login for user: {Username} from IP: {IpAddress}",
        username,
        GetClientIpAddress()
    );
    
    CreateSession(user);
    return true;
}
```

---

## 10. Time-of-Check Time-of-Use (TOCTOU) Errors

### The Problem
Checking a condition and then acting on it later creates a window where the state can change, leading to race conditions and security bypasses.

### Wrong ❌
```csharp
public void WithdrawMoney(int userId, decimal amount)
{
    var balance = GetBalance(userId);
    
    if (balance >= amount)
    {
        // State could change here!
        Thread.Sleep(100); // Simulating processing
        
        // Another transaction could have withdrawn already
        SetBalance(userId, balance - amount);
    }
}
```

### Right ✅
```csharp
public void WithdrawMoney(int userId, decimal amount)
{
    using (var transaction = _dbContext.Database.BeginTransaction())
    {
        try
        {
            // Lock the row for update
            var account = _dbContext.Accounts
                .FromSqlRaw("SELECT * FROM Accounts WHERE UserId = {0} FOR UPDATE", userId)
                .FirstOrDefault();
            
            if (account == null)
                throw new InvalidOperationException("Account not found");
            
            if (account.Balance >= amount)
            {
                // Check and update in same atomic operation
                account.Balance -= amount;
                _dbContext.SaveChanges();
                transaction.Commit();
            }
            else
            {
                throw new InvalidOperationException("Insufficient funds");
            }
        }
        catch
        {
            transaction.Rollback();
            throw;
        }
    }
}

// Alternative: Use optimistic concurrency
public class Account
{
    public int UserId { get; set; }
    public decimal Balance { get; set; }
    
    [Timestamp]
    public byte[] RowVersion { get; set; } // EF Core concurrency token
}

public void WithdrawMoneyOptimistic(int userId, decimal amount)
{
    bool success = false;
    int retries = 3;
    
    while (!success && retries > 0)
    {
        try
        {
            var account = _dbContext.Accounts.Find(userId);
            
            if (account.Balance >= amount)
            {
                account.Balance -= amount;
                _dbContext.SaveChanges(); // Throws if RowVersion changed
                success = true;
            }
        }
        catch (DbUpdateConcurrencyException)
        {
            retries--;
            if (retries == 0) throw;
            // Reload and retry
            _dbContext.Entry(account).Reload();
        }
    }
}
```

---

## 11. Unsafe String Comparisons

### The Problem
Using case-sensitive or culture-dependent string comparisons for security decisions can lead to authentication bypasses.

### Wrong ❌
```csharp
public bool CheckFileAccess(string requestedFile, string[] allowedFiles)
{
    // Case-sensitive comparison can be bypassed
    return allowedFiles.Contains(requestedFile);
}
// Bypass: Request "Admin.txt" when "admin.txt" is blocked

public bool ValidateToken(string providedToken, string expectedToken)
{
    // Vulnerable to timing attacks
    return providedToken == expectedToken;
}
```

### Right ✅
```csharp
public bool CheckFileAccess(string requestedFile, string[] allowedFiles)
{
    // Use case-insensitive, culture-invariant comparison
    return allowedFiles.Contains(
        requestedFile, 
        StringComparer.OrdinalIgnoreCase
    );
}

public bool ValidateToken(string providedToken, string expectedToken)
{
    // Use constant-time comparison to prevent timing attacks
    if (providedToken == null || expectedToken == null)
        return false;
    
    if (providedToken.Length != expectedToken.Length)
        return false;
    
    // Constant-time comparison
    int result = 0;
    for (int i = 0; i < expectedToken.Length; i++)
    {
        result |= providedToken[i] ^ expectedToken[i];
    }
    
    return result == 0;
}

// Or use CryptographicOperations.FixedTimeEquals (available in .NET Core 2.1+)
public bool ValidateTokenSecure(string providedToken, string expectedToken)
{
    byte[] providedBytes = Encoding.UTF8.GetBytes(providedToken);
    byte[] expectedBytes = Encoding.UTF8.GetBytes(expectedToken);
    
    return CryptographicOperations.FixedTimeEquals(providedBytes, expectedBytes);
}
```

---

## 12. Unvalidated Redirects

### The Problem
Following redirects from user input without validation enables phishing attacks and credential theft.

### Wrong ❌
```csharp
[HttpGet]
public IActionResult Login(string returnUrl)
{
    ViewBag.ReturnUrl = returnUrl; // Stored for after login
    return View();
}

[HttpPost]
public IActionResult Login(LoginModel model, string returnUrl)
{
    if (ValidateCredentials(model))
    {
        // Dangerous redirect!
        return Redirect(returnUrl);
    }
    return View(model);
}
// Attacker uses: /login?returnUrl=https://evil.com/fake-login
```

### Right ✅
```csharp
[HttpGet]
public IActionResult Login(string returnUrl)
{
    // Validate and sanitize return URL
    returnUrl = ValidateReturnUrl(returnUrl);
    ViewBag.ReturnUrl = returnUrl;
    return View();
}

[HttpPost]
public IActionResult Login(LoginModel model, string returnUrl)
{
    if (ValidateCredentials(model))
    {
        // Validate again before redirecting
        returnUrl = ValidateReturnUrl(returnUrl);
        return Redirect(returnUrl);
    }
    return View(model);
}

private string ValidateReturnUrl(string returnUrl)
{
    // Only allow local URLs
    if (string.IsNullOrEmpty(returnUrl) || !Url.IsLocalUrl(returnUrl))
    {
        return Url.Action("Index", "Home"); // Safe default
    }
    
    // Additional validation: check against whitelist
    Uri uri;
    if (Uri.TryCreate(returnUrl, UriKind.Relative, out uri))
    {
        return returnUrl;
    }
    
    // If somehow an absolute URL got through, reject it
    return Url.Action("Index", "Home");
}
```

---

## Summary

These code quality and logic issues often slip through code reviews because they're subtle and context-dependent. Key principles to remember:

1. **Always validate and sanitize input** at boundaries
2. **Use appropriate synchronization** for concurrent operations
3. **Dispose resources properly** to prevent leaks
4. **Validate security-relevant calculations** for overflow
5. **Use constant-time comparisons** for secrets
6. **Log security events** comprehensively
7. **Handle errors gracefully** without exposing details
8. **Avoid TOCTOU** by making atomic operations
9. **Never execute dynamic code** from user input
10. **Validate and whitelist** all external commands and paths

