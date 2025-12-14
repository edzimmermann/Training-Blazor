# C#/.NET Input Validation Security: Detailed Guide with Examples

## 1. Trusting User Input Without Validation

### The Problem
Accepting input without validation allows attackers to inject malicious data, bypass business logic, or cause application errors.

### Wrong ❌
```csharp
[HttpPost]
public IActionResult CreateUser(string username, string email, int age)
{
    // No validation!
    var user = new User
    {
        Username = username,
        Email = email,
        Age = age
    };
    
    _userRepository.Add(user);
    return Ok();
}
// Attacker can send: age = -5, email = "not-an-email", username = "<script>alert('XSS')</script>"
```

### Right ✅
```csharp
// Using Data Annotations
public class CreateUserModel
{
    [Required(ErrorMessage = "Username is required")]
    [StringLength(50, MinimumLength = 3, ErrorMessage = "Username must be 3-50 characters")]
    [RegularExpression(@"^[a-zA-Z0-9_]+$", ErrorMessage = "Username can only contain letters, numbers, and underscores")]
    public string Username { get; set; }
    
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email address")]
    [StringLength(100, ErrorMessage = "Email too long")]
    public string Email { get; set; }
    
    [Required(ErrorMessage = "Age is required")]
    [Range(18, 120, ErrorMessage = "Age must be between 18 and 120")]
    public int Age { get; set; }
}

[HttpPost]
public IActionResult CreateUser([FromBody] CreateUserModel model)
{
    // Check ModelState
    if (!ModelState.IsValid)
    {
        return BadRequest(ModelState);
    }
    
    // Additional business logic validation
    if (_userRepository.UsernameExists(model.Username))
    {
        ModelState.AddModelError("Username", "Username already exists");
        return BadRequest(ModelState);
    }
    
    var user = new User
    {
        Username = model.Username,
        Email = model.Email,
        Age = model.Age
    };
    
    _userRepository.Add(user);
    return Ok();
}

// Custom validation attribute
public class NoScriptTagsAttribute : ValidationAttribute
{
    protected override ValidationResult IsValid(object value, ValidationContext validationContext)
    {
        if (value is string str && (str.Contains("<script", StringComparison.OrdinalIgnoreCase) ||
                                     str.Contains("</script", StringComparison.OrdinalIgnoreCase)))
        {
            return new ValidationResult("Input contains potentially dangerous content");
        }
        
        return ValidationResult.Success;
    }
}
```

---

## 2. Missing Input Length Validation

### The Problem
Not validating input length can lead to buffer overflows, denial of service, or database errors.

### Wrong ❌
```csharp
[HttpPost]
public IActionResult PostComment(string comment)
{
    // No length check - could be megabytes of data!
    _commentRepository.Add(new Comment { Text = comment });
    return Ok();
}
```

### Right ✅
```csharp
public class CommentModel
{
    [Required]
    [StringLength(5000, MinimumLength = 1, ErrorMessage = "Comment must be 1-5000 characters")]
    public string Text { get; set; }
}

[HttpPost]
public IActionResult PostComment([FromBody] CommentModel model)
{
    if (!ModelState.IsValid)
        return BadRequest(ModelState);
    
    // Additional validation
    if (model.Text.Length > 5000)
    {
        return BadRequest("Comment too long");
    }
    
    _commentRepository.Add(new Comment { Text = model.Text });
    return Ok();
}

// For file uploads
[HttpPost]
[RequestSizeLimit(10485760)] // 10 MB limit
public async Task<IActionResult> UploadFile(IFormFile file)
{
    if (file == null || file.Length == 0)
        return BadRequest("No file uploaded");
    
    if (file.Length > 10485760) // 10 MB
        return BadRequest("File too large");
    
    // Process file...
    return Ok();
}

// Configure global request size limits in Program.cs
builder.Services.Configure<FormOptions>(options =>
{
    options.MultipartBodyLengthLimit = 10485760; // 10 MB
});

builder.Services.Configure<IISServerOptions>(options =>
{
    options.MaxRequestBodySize = 10485760; // 10 MB
});
```

---

## 3. Not Validating File Upload Types

### The Problem
Accepting any file type allows attackers to upload malicious files, potentially leading to code execution or stored XSS.

### Wrong ❌
```csharp
[HttpPost]
public async Task<IActionResult> UploadFile(IFormFile file)
{
    // Only checking Content-Type header - easily spoofed!
    if (file.ContentType != "image/jpeg")
        return BadRequest("Only JPEG files allowed");
    
    var path = Path.Combine("uploads", file.FileName);
    using (var stream = new FileStream(path, FileMode.Create))
    {
        await file.CopyToAsync(stream);
    }
    
    return Ok();
}
```

### Right ✅
```csharp
[HttpPost]
public async Task<IActionResult> UploadFile(IFormFile file)
{
    if (file == null || file.Length == 0)
        return BadRequest("No file uploaded");
    
    // Validate file size
    if (file.Length > 5242880) // 5 MB
        return BadRequest("File too large");
    
    // Validate file extension (whitelist)
    var allowedExtensions = new[] { ".jpg", ".jpeg", ".png", ".gif" };
    var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
    
    if (string.IsNullOrEmpty(extension) || !allowedExtensions.Contains(extension))
        return BadRequest("Invalid file type");
    
    // Verify actual file content (magic numbers)
    if (!IsValidImageFile(file))
        return BadRequest("File content does not match expected image format");
    
    // Generate safe filename
    var safeFileName = $"{Guid.NewGuid()}{extension}";
    var uploadPath = Path.Combine(_hostEnvironment.WebRootPath, "uploads", safeFileName);
    
    // Ensure upload directory exists
    Directory.CreateDirectory(Path.GetDirectoryName(uploadPath));
    
    using (var stream = new FileStream(uploadPath, FileMode.Create))
    {
        await file.CopyToAsync(stream);
    }
    
    return Ok(new { fileName = safeFileName });
}

private bool IsValidImageFile(IFormFile file)
{
    try
    {
        using (var stream = file.OpenReadStream())
        {
            var buffer = new byte[8];
            stream.Read(buffer, 0, 8);
            
            // Check magic numbers for common image formats
            // PNG: 89 50 4E 47 0D 0A 1A 0A
            if (buffer[0] == 0x89 && buffer[1] == 0x50 && buffer[2] == 0x4E && buffer[3] == 0x47)
                return true;
            
            // JPEG: FF D8 FF
            if (buffer[0] == 0xFF && buffer[1] == 0xD8 && buffer[2] == 0xFF)
                return true;
            
            // GIF: 47 49 46 38
            if (buffer[0] == 0x47 && buffer[1] == 0x49 && buffer[2] == 0x46 && buffer[3] == 0x38)
                return true;
        }
    }
    catch
    {
        return false;
    }
    
    return false;
}

// More comprehensive validation using ImageSharp
public async Task<bool> IsValidImage(IFormFile file)
{
    try
    {
        using (var stream = file.OpenReadStream())
        {
            var image = await Image.LoadAsync(stream);
            
            // Validate image properties
            if (image.Width > 4000 || image.Height > 4000)
                return false;
            
            return true;
        }
    }
    catch
    {
        return false;
    }
}
```

---

## 4. Insufficient Numeric Validation

### The Problem
Not validating numeric ranges can lead to integer overflow, business logic errors, or denial of service.

### Wrong ❌
```csharp
[HttpPost]
public IActionResult PlaceOrder(int quantity, decimal price)
{
    // No validation - negative numbers, overflow, etc.
    var total = quantity * price;
    
    _orderService.CreateOrder(quantity, total);
    return Ok();
}
// Attacker sends: quantity = -10, or quantity = int.MaxValue
```

### Right ✅
```csharp
public class OrderModel
{
    [Required]
    [Range(1, 1000, ErrorMessage = "Quantity must be between 1 and 1000")]
    public int Quantity { get; set; }
    
    [Required]
    [Range(0.01, 999999.99, ErrorMessage = "Price must be between $0.01 and $999,999.99")]
    [RegularExpression(@"^\d+(\.\d{1,2})?$", ErrorMessage = "Price must have at most 2 decimal places")]
    public decimal Price { get; set; }
}

[HttpPost]
public IActionResult PlaceOrder([FromBody] OrderModel model)
{
    if (!ModelState.IsValid)
        return BadRequest(ModelState);
    
    // Additional business logic validation
    if (model.Quantity <= 0)
        return BadRequest("Quantity must be positive");
    
    if (model.Price <= 0)
        return BadRequest("Price must be positive");
    
    // Check for overflow before calculation
    decimal maxTotal = 10000000m; // $10 million
    decimal total;
    
    try
    {
        checked
        {
            total = model.Quantity * model.Price;
        }
        
        if (total > maxTotal)
            return BadRequest("Order total exceeds maximum allowed");
    }
    catch (OverflowException)
    {
        return BadRequest("Order calculation resulted in overflow");
    }
    
    _orderService.CreateOrder(model.Quantity, total);
    return Ok(new { total });
}

// Custom range validation
public class PositiveNumberAttribute : ValidationAttribute
{
    protected override ValidationResult IsValid(object value, ValidationContext validationContext)
    {
        if (value is int intValue && intValue <= 0)
            return new ValidationResult("Value must be positive");
        
        if (value is decimal decValue && decValue <= 0)
            return new ValidationResult("Value must be positive");
        
        return ValidationResult.Success;
    }
}
```

---

## 5. Missing Email Validation

### The Problem
Not properly validating email addresses can lead to invalid data, spam, or injection attacks.

### Wrong ❌
```csharp
[HttpPost]
public IActionResult Subscribe(string email)
{
    // Weak validation
    if (email.Contains("@"))
    {
        _subscriptionService.Add(email);
        return Ok();
    }
    return BadRequest();
}
// Accepts: "abc@", "@example.com", "test@@example.com"
```

### Right ✅
```csharp
public class SubscriptionModel
{
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    [StringLength(254, ErrorMessage = "Email too long")] // RFC 5321
    [RegularExpression(@"^[^@\s]+@[^@\s]+\.[^@\s]+$", ErrorMessage = "Invalid email format")]
    public string Email { get; set; }
}

[HttpPost]
public IActionResult Subscribe([FromBody] SubscriptionModel model)
{
    if (!ModelState.IsValid)
        return BadRequest(ModelState);
    
    // Additional validation
    if (!IsValidEmail(model.Email))
        return BadRequest("Invalid email address");
    
    // Check for disposable email domains (optional)
    if (IsDisposableEmail(model.Email))
        return BadRequest("Disposable email addresses are not allowed");
    
    _subscriptionService.Add(model.Email);
    return Ok();
}

private bool IsValidEmail(string email)
{
    if (string.IsNullOrWhiteSpace(email))
        return false;
    
    try
    {
        // Use MailAddress for validation
        var addr = new System.Net.Mail.MailAddress(email);
        return addr.Address == email;
    }
    catch
    {
        return false;
    }
}

private bool IsDisposableEmail(string email)
{
    var disposableDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "tempmail.com",
        "throwaway.email",
        "guerrillamail.com",
        "10minutemail.com"
    };
    
    var domain = email.Split('@').LastOrDefault();
    return domain != null && disposableDomains.Contains(domain);
}

// More comprehensive email validation
public class EmailValidationAttribute : ValidationAttribute
{
    protected override ValidationResult IsValid(object value, ValidationContext validationContext)
    {
        if (value is not string email)
            return new ValidationResult("Invalid email type");
        
        if (string.IsNullOrWhiteSpace(email))
            return new ValidationResult("Email is required");
        
        // Length check
        if (email.Length > 254)
            return new ValidationResult("Email too long");
        
        // Basic format check
        if (!email.Contains("@") || email.StartsWith("@") || email.EndsWith("@"))
            return new ValidationResult("Invalid email format");
        
        var parts = email.Split('@');
        if (parts.Length != 2)
            return new ValidationResult("Invalid email format");
        
        var localPart = parts[0];
        var domain = parts[1];
        
        // Local part validation
        if (localPart.Length == 0 || localPart.Length > 64)
            return new ValidationResult("Invalid email local part");
        
        // Domain validation
        if (domain.Length == 0 || !domain.Contains("."))
            return new ValidationResult("Invalid email domain");
        
        // Use MailAddress for final validation
        try
        {
            var addr = new System.Net.Mail.MailAddress(email);
            if (addr.Address != email)
                return new ValidationResult("Invalid email format");
        }
        catch
        {
            return new ValidationResult("Invalid email format");
        }
        
        return ValidationResult.Success;
    }
}
```

---

## 6. URL Validation Issues

### The Problem
Not properly validating URLs allows open redirects, SSRF attacks, or malicious protocols.

### Wrong ❌
```csharp
[HttpGet]
public IActionResult Redirect(string url)
{
    // Dangerous - allows any URL!
    return Redirect(url);
}
// Attacker uses: ?url=javascript:alert('XSS') or ?url=http://evil.com
```

### Right ✅
```csharp
public class RedirectModel
{
    [Required]
    [Url(ErrorMessage = "Invalid URL format")]
    [StringLength(2048, ErrorMessage = "URL too long")]
    public string Url { get; set; }
}

[HttpGet]
public IActionResult Redirect(string url)
{
    if (string.IsNullOrWhiteSpace(url))
        return BadRequest("URL is required");
    
    // Only allow local URLs
    if (Url.IsLocalUrl(url))
    {
        return Redirect(url);
    }
    
    // Or validate against whitelist for external URLs
    if (IsWhitelistedUrl(url))
    {
        return Redirect(url);
    }
    
    return BadRequest("Invalid redirect URL");
}

private bool IsWhitelistedUrl(string url)
{
    if (!Uri.TryCreate(url, UriKind.Absolute, out Uri uriResult))
        return false;
    
    // Only allow http and https
    if (uriResult.Scheme != Uri.UriSchemeHttp && uriResult.Scheme != Uri.UriSchemeHttps)
        return false;
    
    // Whitelist allowed domains
    var allowedDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "example.com",
        "www.example.com",
        "trusted-partner.com"
    };
    
    return allowedDomains.Contains(uriResult.Host);
}

// Custom URL validation attribute
public class SafeUrlAttribute : ValidationAttribute
{
    private readonly bool _allowExternal;
    
    public SafeUrlAttribute(bool allowExternal = false)
    {
        _allowExternal = allowExternal;
    }
    
    protected override ValidationResult IsValid(object value, ValidationContext validationContext)
    {
        if (value is not string url)
            return ValidationResult.Success;
        
        if (string.IsNullOrWhiteSpace(url))
            return ValidationResult.Success;
        
        // Check if it's a valid URI
        if (!Uri.TryCreate(url, UriKind.RelativeOrAbsolute, out Uri uriResult))
            return new ValidationResult("Invalid URL format");
        
        // If absolute URI, validate scheme
        if (uriResult.IsAbsoluteUri)
        {
            if (uriResult.Scheme != Uri.UriSchemeHttp && uriResult.Scheme != Uri.UriSchemeHttps)
                return new ValidationResult("Only HTTP and HTTPS URLs are allowed");
            
            if (!_allowExternal)
                return new ValidationResult("External URLs are not allowed");
        }
        
        return ValidationResult.Success;
    }
}
```

---

## 7. Date and Time Validation

### The Problem
Not validating dates can lead to business logic errors, invalid database entries, or application crashes.

### Wrong ❌
```csharp
[HttpPost]
public IActionResult BookAppointment(DateTime appointmentDate)
{
    // No validation - could be in the past, too far in future, invalid, etc.
    _appointmentService.Book(appointmentDate);
    return Ok();
}
```

### Right ✅
```csharp
public class AppointmentModel
{
    [Required]
    [DataType(DataType.DateTime)]
    [FutureDate(ErrorMessage = "Appointment must be in the future")]
    [DateRange(MinDaysFromNow = 1, MaxDaysFromNow = 90, 
        ErrorMessage = "Appointment must be between 1 and 90 days from now")]
    public DateTime AppointmentDate { get; set; }
}

[HttpPost]
public IActionResult BookAppointment([FromBody] AppointmentModel model)
{
    if (!ModelState.IsValid)
        return BadRequest(ModelState);
    
    // Additional validation
    var now = DateTime.UtcNow;
    
    if (model.AppointmentDate <= now)
        return BadRequest("Appointment must be in the future");
    
    if (model.AppointmentDate > now.AddDays(90))
        return BadRequest("Appointment too far in the future");
    
    // Check business hours
    if (model.AppointmentDate.Hour < 9 || model.AppointmentDate.Hour >= 17)
        return BadRequest("Appointments must be between 9 AM and 5 PM");
    
    // Check for weekends
    if (model.AppointmentDate.DayOfWeek == DayOfWeek.Saturday || 
        model.AppointmentDate.DayOfWeek == DayOfWeek.Sunday)
        return BadRequest("Appointments not available on weekends");
    
    _appointmentService.Book(model.AppointmentDate);
    return Ok();
}

// Custom date validation attributes
public class FutureDateAttribute : ValidationAttribute
{
    protected override ValidationResult IsValid(object value, ValidationContext validationContext)
    {
        if (value is DateTime date)
        {
            if (date <= DateTime.UtcNow)
                return new ValidationResult("Date must be in the future");
        }
        
        return ValidationResult.Success;
    }
}

public class DateRangeAttribute : ValidationAttribute
{
    public int MinDaysFromNow { get; set; }
    public int MaxDaysFromNow { get; set; }
    
    protected override ValidationResult IsValid(object value, ValidationContext validationContext)
    {
        if (value is DateTime date)
        {
            var now = DateTime.UtcNow;
            var minDate = now.AddDays(MinDaysFromNow);
            var maxDate = now.AddDays(MaxDaysFromNow);
            
            if (date < minDate || date > maxDate)
                return new ValidationResult(ErrorMessage ?? 
                    $"Date must be between {MinDaysFromNow} and {MaxDaysFromNow} days from now");
        }
        
        return ValidationResult.Success;
    }
}

public class BusinessHoursAttribute : ValidationAttribute
{
    public int StartHour { get; set; } = 9;
    public int EndHour { get; set; } = 17;
    
    protected override ValidationResult IsValid(object value, ValidationContext validationContext)
    {
        if (value is DateTime date)
        {
            if (date.Hour < StartHour || date.Hour >= EndHour)
                return new ValidationResult(
                    $"Time must be between {StartHour}:00 and {EndHour}:00");
        }
        
        return ValidationResult.Success;
    }
}
```

---

## 8. Phone Number Validation

### The Problem
Not validating phone numbers properly leads to invalid data and failed communications.

### Wrong ❌
```csharp
[HttpPost]
public IActionResult UpdatePhone(string phoneNumber)
{
    // Weak validation
    if (phoneNumber.Length >= 10)
    {
        _userService.UpdatePhone(phoneNumber);
        return Ok();
    }
    return BadRequest();
}
```

### Right ✅
```csharp
public class PhoneNumberModel
{
    [Required]
    [Phone(ErrorMessage = "Invalid phone number")]
    [RegularExpression(@"^\+?1?\d{9,15}$", ErrorMessage = "Invalid phone number format")]
    [StringLength(20, MinimumLength = 10, ErrorMessage = "Phone number must be 10-20 characters")]
    public string PhoneNumber { get; set; }
}

[HttpPost]
public IActionResult UpdatePhone([FromBody] PhoneNumberModel model)
{
    if (!ModelState.IsValid)
        return BadRequest(ModelState);
    
    // Normalize and validate
    var normalizedPhone = NormalizePhoneNumber(model.PhoneNumber);
    
    if (!IsValidPhoneNumber(normalizedPhone))
        return BadRequest("Invalid phone number");
    
    _userService.UpdatePhone(normalizedPhone);
    return Ok();
}

private string NormalizePhoneNumber(string phone)
{
    // Remove all non-digit characters except +
    return Regex.Replace(phone, @"[^\d+]", "");
}

private bool IsValidPhoneNumber(string phone)
{
    // Remove + if present
    var digits = phone.TrimStart('+');
    
    // Must be 10-15 digits
    if (digits.Length < 10 || digits.Length > 15)
        return false;
    
    // Must contain only digits
    if (!digits.All(char.IsDigit))
        return false;
    
    return true;
}

// Using libphonenumber-csharp for comprehensive validation
public class PhoneValidator
{
    private readonly PhoneNumberUtil _phoneUtil = PhoneNumberUtil.GetInstance();
    
    public bool IsValid(string phoneNumber, string countryCode = "US")
    {
        try
        {
            var number = _phoneUtil.Parse(phoneNumber, countryCode);
            return _phoneUtil.IsValidNumber(number);
        }
        catch
        {
            return false;
        }
    }
    
    public string Format(string phoneNumber, string countryCode = "US")
    {
        try
        {
            var number = _phoneUtil.Parse(phoneNumber, countryCode);
            return _phoneUtil.Format(number, PhoneNumberFormat.E164);
        }
        catch
        {
            return null;
        }
    }
}
```

---

## 9. Regex Validation and ReDoS Prevention

### The Problem
Complex or poorly written regular expressions can cause catastrophic backtracking, leading to denial of service (ReDoS).

### Wrong ❌
```csharp
public bool ValidateInput(string input)
{
    // Catastrophic backtracking! 
    var regex = new Regex(@"^(a+)+$");
    return regex.IsMatch(input);
}
// Input like "aaaaaaaaaaaaaaaaaaaaaaaaaaab" causes exponential time complexity
```

### Right ✅
```csharp
public bool ValidateInput(string input)
{
    // Simple, efficient regex
    var regex = new Regex(@"^a+$", RegexOptions.None, TimeSpan.FromMilliseconds(100));
    
    try
    {
        return regex.IsMatch(input);
    }
    catch (RegexMatchTimeoutException)
    {
        // Regex took too long - potential ReDoS attempt
        _logger.LogWarning("Regex timeout for input length: {Length}", input.Length);
        return false;
    }
}

// Safe email regex with timeout
public bool IsValidEmailRegex(string email)
{
    var regex = new Regex(
        @"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
        RegexOptions.Compiled,
        TimeSpan.FromMilliseconds(100)
    );
    
    try
    {
        return regex.IsMatch(email);
    }
    catch (RegexMatchTimeoutException)
    {
        return false;
    }
}

// Guidelines for safe regex:
// 1. Use timeouts
// 2. Avoid nested quantifiers: (a+)+, (a*)*
// 3. Avoid alternations with overlap: (a|a)*
// 4. Keep patterns simple
// 5. Test with long inputs
// 6. Use RegexOptions.Compiled for frequently used patterns

public class SafeRegexValidator
{
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromMilliseconds(100);
    
    public static bool IsMatch(string input, string pattern)
    {
        if (string.IsNullOrEmpty(input) || string.IsNullOrEmpty(pattern))
            return false;
        
        try
        {
            var regex = new Regex(pattern, RegexOptions.None, DefaultTimeout);
            return regex.IsMatch(input);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            // Invalid regex pattern
            return false;
        }
    }
}
```

---

## 10. Collection and Array Validation

### The Problem
Not validating collection sizes or contents can lead to denial of service or injection attacks.

### Wrong ❌
```csharp
[HttpPost]
public IActionResult ProcessItems(List<string> items)
{
    // No validation on collection size or contents!
    foreach (var item in items)
    {
        _itemService.Process(item);
    }
    return Ok();
}
// Attacker sends thousands or millions of items
```

### Right ✅
```csharp
public class ItemsModel
{
    [Required]
    [MinLength(1, ErrorMessage = "At least one item is required")]
    [MaxLength(100, ErrorMessage = "Maximum 100 items allowed")]
    public List<ItemModel> Items { get; set; }
}

public class ItemModel
{
    [Required]
    [StringLength(100, MinimumLength = 1)]
    [RegularExpression(@"^[a-zA-Z0-9\s-]+$")]
    public string Name { get; set; }
    
    [Range(1, 1000)]
    public int Quantity { get; set; }
}

[HttpPost]
public IActionResult ProcessItems([FromBody] ItemsModel model)
{
    if (!ModelState.IsValid)
        return BadRequest(ModelState);
    
    // Additional validation
    if (model.Items == null || model.Items.Count == 0)
        return BadRequest("No items provided");
    
    if (model.Items.Count > 100)
        return BadRequest("Too many items");
    
    // Validate each item
    foreach (var item in model.Items)
    {
        if (string.IsNullOrWhiteSpace(item.Name))
            return BadRequest("Item name cannot be empty");
        
        if (item.Quantity <= 0)
            return BadRequest("Item quantity must be positive");
    }
    
    // Check for duplicates
    var duplicates = model.Items
        .GroupBy(x => x.Name)
        .Where(g => g.Count() > 1)
        .Select(g => g.Key)
        .ToList();
    
    if (duplicates.Any())
        return BadRequest($"Duplicate items found: {string.Join(", ", duplicates)}");
    
    _itemService.ProcessBatch(model.Items);
    return Ok();
}

// Custom collection validation
public class MaxCollectionSizeAttribute : ValidationAttribute
{
    private readonly int _maxSize;
    
    public MaxCollectionSizeAttribute(int maxSize)
    {
        _maxSize = maxSize;
    }
    
    protected override ValidationResult IsValid(object value, ValidationContext validationContext)
    {
        if (value is ICollection collection && collection.Count > _maxSize)
        {
            return new ValidationResult($"Collection cannot contain more than {_maxSize} items");
        }
        
        return ValidationResult.Success;
    }
}
```

---

## Best Practices Summary

### Always Do:
1. **Use Data Annotations** for declarative validation
2. **Validate on server side** - never trust client validation alone
3. **Whitelist allowed values** when possible
4. **Set maximum lengths** for all string inputs
5. **Validate numeric ranges** to prevent overflow
6. **Use timeouts for regex** to prevent ReDoS
7. **Validate file types** by content, not just extension
8. **Sanitize output** even after validation
9. **Log validation failures** for security monitoring
10. **Return generic error messages** to users (don't reveal validation logic)

### Never Do:
1. **Never trust user input** without validation
2. **Never validate only on client side**
3. **Never use blacklists** - prefer whitelists
4. **Never skip validation** for "trusted" users
5. **Never reveal sensitive info** in validation errors
6. **Never use complex regex** without timeouts
7. **Never accept unlimited input** sizes
