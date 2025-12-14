# C#/.NET Authentication & Authorization Security: Detailed Guide with Examples

## 1. Not Using ASP.NET Identity Framework

### The Problem
Implementing custom authentication from scratch often introduces security vulnerabilities due to missing essential features like proper password hashing, account lockout, and session management.

### Wrong ❌
```csharp
public class CustomAuthController : Controller
{
    private readonly IUserRepository _userRepository;
    
    [HttpPost]
    public IActionResult Login(string username, string password)
    {
        var user = _userRepository.GetByUsername(username);
        
        // Weak password verification
        if (user != null && user.Password == password)
        {
            // Insecure session management
            HttpContext.Session.SetString("UserId", user.Id.ToString());
            HttpContext.Session.SetString("Username", user.Username);
            
            return RedirectToAction("Dashboard");
        }
        
        return View("Login");
    }
}
```

### Right ✅
```csharp
// Configure in Program.cs
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // Password settings
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredLength = 12;
    options.Password.RequiredUniqueChars = 4;
    
    // Lockout settings
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;
    
    // User settings
    options.User.RequireUniqueEmail = true;
    
    // Sign-in settings
    options.SignIn.RequireConfirmedEmail = true;
    options.SignIn.RequireConfirmedAccount = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
    options.SlidingExpiration = true;
    options.LoginPath = "/Account/Login";
    options.AccessDeniedPath = "/Account/AccessDenied";
});

// Controller using Identity
public class AccountController : Controller
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        if (!ModelState.IsValid)
            return View(model);
        
        var result = await _signInManager.PasswordSignInAsync(
            model.Email,
            model.Password,
            model.RememberMe,
            lockoutOnFailure: true);
        
        if (result.Succeeded)
        {
            return RedirectToAction("Dashboard");
        }
        
        if (result.IsLockedOut)
        {
            return View("Lockout");
        }
        
        ModelState.AddModelError(string.Empty, "Invalid login attempt.");
        return View(model);
    }
}
```

---

## 2. Missing Account Lockout Protection

### The Problem
Without account lockout, attackers can perform unlimited brute force attempts.

### Wrong ❌
```csharp
[HttpPost]
public async Task<IActionResult> Login(string username, string password)
{
    var user = await _userRepository.GetByUsernameAsync(username);
    
    if (user == null || !VerifyPassword(password, user.PasswordHash))
    {
        return View("Login", new { Error = "Invalid credentials" });
    }
    
    await SignInAsync(user);
    return RedirectToAction("Dashboard");
}
```

### Right ✅
```csharp
public class SecureLoginController : Controller
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        if (!ModelState.IsValid)
            return View(model);
        
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
        {
            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return View(model);
        }
        
        if (await _userManager.IsLockedOutAsync(user))
        {
            var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);
            return View("Lockout", new LockoutViewModel { LockoutEnd = lockoutEnd });
        }
        
        var result = await _signInManager.PasswordSignInAsync(
            model.Email,
            model.Password,
            model.RememberMe,
            lockoutOnFailure: true);
        
        if (result.Succeeded)
        {
            await _userManager.ResetAccessFailedCountAsync(user);
            return RedirectToAction("Dashboard");
        }
        
        if (result.IsLockedOut)
        {
            return View("Lockout");
        }
        
        await _userManager.AccessFailedAsync(user);
        ModelState.AddModelError(string.Empty, "Invalid login attempt.");
        return View(model);
    }
}
```

---

## 3. Missing Multi-Factor Authentication

### The Problem
Relying solely on passwords leaves accounts vulnerable to credential theft.

### Wrong ❌
```csharp
[HttpPost]
public async Task<IActionResult> Login(string email, string password)
{
    var user = await _userManager.FindByEmailAsync(email);
    
    if (user != null && await _userManager.CheckPasswordAsync(user, password))
    {
        await _signInManager.SignInAsync(user, isPersistent: false);
        return RedirectToAction("Dashboard");
    }
    
    return View("Login");
}
```

### Right ✅
```csharp
// Enable 2FA
public class TwoFactorController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    
    [HttpGet]
    [Authorize]
    public async Task<IActionResult> EnableAuthenticator()
    {
        var user = await _userManager.GetUserAsync(User);
        await _userManager.ResetAuthenticatorKeyAsync(user);
        var key = await _userManager.GetAuthenticatorKeyAsync(user);
        
        return View(new EnableAuthenticatorViewModel
        {
            SharedKey = FormatKey(key),
            AuthenticatorUri = GenerateQrCodeUri(user.Email, key)
        });
    }
    
    [HttpPost]
    [Authorize]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> EnableAuthenticator(EnableAuthenticatorViewModel model)
    {
        if (!ModelState.IsValid)
            return View(model);
        
        var user = await _userManager.GetUserAsync(User);
        var verificationCode = model.Code.Replace(" ", "").Replace("-", "");
        
        var is2faTokenValid = await _userManager.VerifyTwoFactorTokenAsync(
            user,
            _userManager.Options.Tokens.AuthenticatorTokenProvider,
            verificationCode);
        
        if (!is2faTokenValid)
        {
            ModelState.AddModelError("Code", "Verification code is invalid.");
            return View(model);
        }
        
        await _userManager.SetTwoFactorEnabledAsync(user, true);
        var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
        
        return View("ShowRecoveryCodes", recoveryCodes.ToArray());
    }
    
    private string FormatKey(string key)
    {
        var result = new StringBuilder();
        int currentPosition = 0;
        while (currentPosition + 4 < key.Length)
        {
            result.Append(key.Substring(currentPosition, 4)).Append(" ");
            currentPosition += 4;
        }
        if (currentPosition < key.Length)
        {
            result.Append(key.Substring(currentPosition));
        }
        return result.ToString().ToLowerInvariant();
    }
    
    private string GenerateQrCodeUri(string email, string key)
    {
        return string.Format(
            "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6",
            "MyApp",
            email,
            key);
    }
}
```

---

## 4. Not Invalidating Sessions on Logout

### The Problem
If sessions aren't properly invalidated, stolen session cookies can continue to be used.

### Wrong ❌
```csharp
[HttpPost]
public IActionResult Logout()
{
    return RedirectToAction("Index", "Home");
}
```

### Right ✅
```csharp
public class SecureLogoutController : Controller
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        HttpContext.Session.Clear();
        
        Response.Headers["Cache-Control"] = "no-cache, no-store, must-revalidate";
        Response.Headers["Pragma"] = "no-cache";
        Response.Headers["Expires"] = "0";
        
        return RedirectToAction("Index", "Home");
    }
}
```

---

## 5. Missing Authorization Checks

### The Problem
Failing to verify user permissions on every request allows unauthorized access.

### Wrong ❌
```csharp
[Authorize]
public IActionResult DeleteUser(int userId)
{
    _userService.Delete(userId);
    return Ok();
}
```

### Right ✅
```csharp
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RequireAdminRole", policy =>
        policy.RequireRole("Admin"));
    
    options.AddPolicy("CanDeleteUsers", policy =>
        policy.RequireClaim("Permission", "DeleteUsers"));
});

[Authorize(Policy = "RequireAdminRole")]
[HttpDelete]
public async Task<IActionResult> DeleteUser(int userId)
{
    var user = await _userService.GetByIdAsync(userId);
    if (user == null)
        return NotFound();
    
    var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
    if (user.Id.ToString() == currentUserId)
    {
        return BadRequest("Cannot delete your own account");
    }
    
    await _userService.DeleteAsync(userId);
    return NoContent();
}

[Authorize]
[HttpGet]
public async Task<IActionResult> GetUserData(int userId)
{
    var user = await _userService.GetByIdAsync(userId);
    if (user == null)
        return NotFound();
    
    var authResult = await _authorizationService.AuthorizeAsync(
        User,
        user,
        "CanViewUserData");
    
    if (!authResult.Succeeded)
        return Forbid();
    
    return Json(await _userService.GetUserDataAsync(userId));
}
```

---

## 6. Trusting Client-Side Authorization

### The Problem
Client-side checks can be bypassed by modifying client code.

### Wrong ❌
```csharp
@if (User.IsInRole("Admin"))
{
    <button onclick="deleteUser()">Delete</button>
}

[HttpPost]
public IActionResult DeleteUser(int userId)
{
    _userService.Delete(userId);
    return Ok();
}
```

### Right ✅
```csharp
@if (User.IsInRole("Admin"))
{
    <button onclick="deleteUser()">Delete</button>
}

[Authorize(Roles = "Admin")]
[HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> DeleteUser(int userId)
{
    if (!User.IsInRole("Admin"))
        return Forbid();
    
    var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
    if (userId.ToString() == currentUserId)
        return BadRequest("Cannot delete your own account");
    
    await _userService.DeleteAsync(userId);
    return NoContent();
}
```

---

## 7. Not Using Secure Cookie Flags

### The Problem
Without proper cookie flags, authentication cookies can be stolen or manipulated.

### Wrong ❌
```csharp
services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = false;
    options.Cookie.SecurePolicy = CookieSecurePolicy.None;
    options.Cookie.SameSite = SameSiteMode.None;
});
```

### Right ✅
```csharp
services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.Name = "MyApp.Auth";
    options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
    options.SlidingExpiration = true;
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.AccessDeniedPath = "/Account/AccessDenied";
});

services.AddAntiforgery(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.HeaderName = "X-CSRF-TOKEN";
});
```

---

## 8. Weak JWT Token Implementation

### The Problem
Improper JWT configuration can lead to token forgery or information disclosure.

### Wrong ❌
```csharp
[HttpPost]
public IActionResult Login(LoginModel model)
{
    if (ValidateCredentials(model.Username, model.Password))
    {
        var key = Encoding.ASCII.GetBytes("mysecretkey");
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim("username", model.Username),
                new Claim("password", model.Password)
            }),
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256)
        };
        
        var token = new JwtSecurityTokenHandler().CreateToken(tokenDescriptor);
        return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token) });
    }
    
    return Unauthorized();
}
```

### Right ✅
```csharp
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
.AddJwtBearer(options =>
{
    var key = Encoding.UTF8.GetBytes(builder.Configuration["Jwt:SecretKey"]);
    
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidateAudience = true,
        ValidAudience = builder.Configuration["Jwt:Audience"],
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero,
        RequireExpirationTime = true,
        RequireSignedTokens = true
    };
});

public class JwtTokenService
{
    public TokenResponse GenerateToken(User user)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };
        
        foreach (var role in user.Roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }
        
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:SecretKey"]));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);
        
        var token = new JwtSecurityToken(
            issuer: _config["Jwt:Issuer"],
            audience: _config["Jwt:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(15),
            signingCredentials: creds);
        
        return new TokenResponse
        {
            AccessToken = new JwtSecurityTokenHandler().WriteToken(token),
            RefreshToken = GenerateRefreshToken(),
            ExpiresIn = 900
        };
    }
    
    private string GenerateRefreshToken()
    {
        return Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
    }
}
```

---

## 9. Missing CSRF Protection

### The Problem
Without CSRF tokens, attackers can trick users into performing unwanted actions.

### Wrong ❌
```csharp
[HttpPost]
public IActionResult TransferMoney(int toAccount, decimal amount)
{
    var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
    _bankService.Transfer(userId, toAccount, amount);
    return Ok();
}
```

### Right ✅
```csharp
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-CSRF-TOKEN";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
});

[HttpPost("transfer")]
[Authorize]
[ValidateAntiForgeryToken]
public async Task<IActionResult> Transfer([FromBody] TransferRequest request)
{
    if (!ModelState.IsValid)
        return BadRequest(ModelState);
    
    var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
    await _bankService.TransferAsync(userId, request.ToAccount, request.Amount);
    
    return Ok();
}
```

---

## 10. Insecure Session Management

### The Problem
Poor session management can lead to session hijacking or fixation.

### Wrong ❌
```csharp
public string CreateSession(User user)
{
    var sessionId = $"{user.Id}_{DateTime.Now.Ticks}";
    HttpContext.Session.SetString("SessionId", sessionId);
    return sessionId;
}
```

### Right ✅
```csharp
builder.Services.AddSession(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.IdleTimeout = TimeSpan.FromMinutes(30);
});

builder.Services.AddStackExchangeRedisCache(options =>
{
    options.Configuration = builder.Configuration.GetConnectionString("Redis");
});

public class SecureSessionService
{
    public async Task<string> CreateSessionAsync(User user)
    {
        var sessionId = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        
        var sessionData = new UserSession
        {
            SessionId = sessionId,
            UserId = user.Id.ToString(),
            CreatedAt = DateTime.UtcNow,
            LastActivity = DateTime.UtcNow
        };
        
        await _cache.SetStringAsync(
            $"session:{sessionId}",
            JsonSerializer.Serialize(sessionData),
            new DistributedCacheEntryOptions
            {
                SlidingExpiration = TimeSpan.FromMinutes(30)
            });
        
        return sessionId;
    }
}
```

---

## 11. Privilege Escalation

### The Problem
Not checking permissions at every level allows privilege escalation.

### Wrong ❌
```csharp
[HttpPut("users/{id}")]
public async Task<IActionResult> UpdateUser(int id, UpdateUserModel model)
{
    var user = await _userService.GetByIdAsync(id);
    user.Role = model.Role;
    await _userService.UpdateAsync(user);
    return Ok();
}
```

### Right ✅
```csharp
[HttpPut("{id}")]
[Authorize]
public async Task<IActionResult> UpdateUser(int id, UpdateUserModel model)
{
    var user = await _userService.GetByIdAsync(id);
    if (user == null)
        return NotFound();
    
    var editAuth = await _authorizationService.AuthorizeAsync(User, user, "CanEditUser");
    if (!editAuth.Succeeded)
        return Forbid();
    
    user.Email = model.Email;
    
    if (model.Role != null && model.Role != user.Role)
    {
        var roleAuth = await _authorizationService.AuthorizeAsync(User, "CanChangeRoles");
        if (!roleAuth.Succeeded)
            return Forbid();
        
        if (User.FindFirstValue(ClaimTypes.NameIdentifier) == id.ToString())
        {
            var adminCount = await _userService.CountAdminsAsync();
            if (adminCount <= 1 && model.Role != "Admin")
                return BadRequest("Cannot remove the last admin");
        }
        
        user.Role = model.Role;
    }
    
    await _userService.UpdateAsync(user);
    return Ok();
}
```

---

## 12. Timing Attacks

### The Problem
Variable response times can reveal whether a username exists.

### Wrong ❌
```csharp
[HttpPost]
public async Task<IActionResult> Login(string username, string password)
{
    var user = await _userRepository.GetByUsernameAsync(username);
    
    if (user == null)
        return Unauthorized();
    
    if (!VerifyPassword(password, user.PasswordHash))
        return Unauthorized();
    
    return Ok(GenerateToken(user));
}
```

### Right ✅
```csharp
[HttpPost]
public async Task<IActionResult> Login(LoginModel model)
{
    var user = await _userRepository.GetByUsernameAsync(model.Username);
    
    string hashToVerify = user != null ? user.PasswordHash : GenerateDummyHash();
    bool passwordValid = VerifyPassword(model.Password, hashToVerify);
    bool loginSuccess = user != null && passwordValid;
    
    if (!loginSuccess)
    {
        await Task.Delay(RandomNumberGenerator.GetInt32(100, 500));
        return Unauthorized(new { Message = "Invalid username or password" });
    }
    
    return Ok(GenerateToken(user));
}

private string GenerateDummyHash()
{
    return BCrypt.Net.BCrypt.HashPassword("DummyPassword123!");
}
```

---

## Best Practices Summary

### Authentication:
- Use ASP.NET Identity
- Implement MFA
- Hash passwords properly
- Account lockout protection
- Session management

### Authorization:
- Check permissions everywhere
- Use policies
- Resource-based authorization
- Never trust client
- Least privilege

### Tokens & Sessions:
- Secure cookies
- Short-lived tokens
- Refresh tokens
- Token revocation
- Distributed cache

### Security:
- CSRF protection
- Security headers
- Rate limiting
- Logging
- Monitoring