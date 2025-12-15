# C#/.NET API Security: Detailed Guide with Examples

## 1. Missing Rate Limiting

### The Problem
Without rate limiting, APIs can be abused for DoS attacks, brute force attempts, or resource exhaustion.

### Wrong ❌
```csharp
[HttpPost("login")]
public async Task<IActionResult> Login([FromBody] LoginRequest request)
{
    // No rate limiting - unlimited login attempts!
    var result = await _authService.AuthenticateAsync(request.Email, request.Password);
    return result.Success ? Ok(new { Token = result.Token }) : Unauthorized();
}
```

### Right ✅
```csharp
// Install: AspNetCoreRateLimit
builder.Services.Configure<IpRateLimitOptions>(options =>
{
    options.GeneralRules = new List<RateLimitRule>
    {
        new RateLimitRule { Endpoint = "*", Period = "1s", Limit = 10 },
        new RateLimitRule { Endpoint = "*", Period = "1m", Limit = 100 }
    };
});

// Custom rate limiting
public class RateLimitAttribute : ActionFilterAttribute
{
    private readonly int _maxRequests;
    private readonly TimeSpan _timeWindow;
    
    public override async Task OnActionExecutionAsync(
        ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var cache = context.HttpContext.RequestServices.GetRequiredService<IDistributedCache>();
        var userId = context.HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier)
            ?? context.HttpContext.Connection.RemoteIpAddress?.ToString();
        
        var key = $"ratelimit:{userId}";
        var countStr = await cache.GetStringAsync(key);
        int count = string.IsNullOrEmpty(countStr) ? 0 : int.Parse(countStr);
        
        if (count >= _maxRequests)
        {
            context.Result = new StatusCodeResult(429);
            return;
        }
        
        await cache.SetStringAsync(key, (count + 1).ToString(),
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = _timeWindow });
        
        await next();
    }
}

[HttpPost("login")]
[RateLimit(5, 60)] // 5 attempts per minute
public async Task<IActionResult> Login([FromBody] LoginRequest request)
{
    var result = await _authService.AuthenticateAsync(request.Email, request.Password);
    return result.Success ? Ok(new { Token = result.Token }) : Unauthorized();
}
```

---

## 2. Missing API Versioning

### The Problem
Without versioning, it's difficult to maintain backward compatibility and security updates.

### Wrong ❌
```csharp
[ApiController]
[Route("api/users")]
public class UsersController : ControllerBase
{
    [HttpGet("{id}")]
    public IActionResult GetUser(int id)
    {
        return Ok(_userService.GetById(id));
    }
}
```

### Right ✅
```csharp
builder.Services.AddApiVersioning(options =>
{
    options.DefaultApiVersion = new ApiVersion(1, 0);
    options.AssumeDefaultVersionWhenUnspecified = true;
    options.ReportApiVersions = true;
});

[ApiController]
[Route("api/v{version:apiVersion}/users")]
[ApiVersion("1.0")]
public class UsersV1Controller : ControllerBase
{
    [HttpGet("{id}")]
    public IActionResult GetUser(int id)
    {
        return Ok(_userService.GetById(id));
    }
}

[ApiController]
[Route("api/v{version:apiVersion}/users")]
[ApiVersion("2.0")]
[Authorize]
public class UsersV2Controller : ControllerBase
{
    [HttpGet("{id}")]
    public async Task<IActionResult> GetUser(int id)
    {
        var user = await _userService.GetByIdAsync(id);
        var authResult = await _authService.AuthorizeAsync(User, user, "CanViewUser");
        return authResult.Succeeded ? Ok(user) : Forbid();
    }
}
```

---

## 3. Exposing Internal Object Structures

### The Problem
Returning internal entities exposes implementation details and sensitive information.

### Wrong ❌
```csharp
[HttpGet("{id}")]
public IActionResult GetUser(int id)
{
    var user = _context.Users
        .Include(u => u.PasswordHistory)
        .Include(u => u.SecurityLogs)
        .FirstOrDefault(u => u.Id == id);
    return Ok(user); // Exposes PasswordHash, etc.
}
```

### Right ✅
```csharp
public class UserDto
{
    public int Id { get; set; }
    public string Username { get; set; }
    public string Email { get; set; }
    public DateTime CreatedAt { get; set; }
}

[HttpGet("{id}")]
public async Task<IActionResult> GetUser(int id)
{
    var user = await _context.Users
        .Where(u => u.Id == id)
        .Select(u => new UserDto
        {
            Id = u.Id,
            Username = u.Username,
            Email = u.Email,
            CreatedAt = u.CreatedAt
        })
        .FirstOrDefaultAsync();
    
    if (user == null) return NotFound();
    
    var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
    if (user.Id.ToString() != currentUserId && !User.IsInRole("Admin"))
        return Forbid();
    
    return Ok(user);
}
```

---

## 4. Not Validating Content-Type

### The Problem
Accepting any Content-Type can lead to injection attacks or unexpected behavior.

### Wrong ❌
```csharp
[HttpPost]
public IActionResult CreateUser([FromBody] object userData)
{
    var user = JsonSerializer.Deserialize<User>(userData.ToString());
    _userService.Create(user);
    return Ok();
}
```

### Right ✅
```csharp
builder.Services.AddControllers(options =>
{
    options.ReturnHttpNotAcceptable = true;
    options.OutputFormatters.RemoveType<XmlDataContractSerializerOutputFormatter>();
})
.AddJsonOptions(options =>
{
    options.JsonSerializerOptions.MaxDepth = 32;
    options.JsonSerializerOptions.AllowTrailingCommas = false;
});

public class ContentTypeValidationMiddleware
{
    private readonly RequestDelegate _next;
    
    public async Task InvokeAsync(HttpContext context)
    {
        if (context.Request.Method == "POST" || context.Request.Method == "PUT")
        {
            var contentType = context.Request.ContentType?.Split(';')[0].Trim();
            if (contentType != "application/json")
            {
                context.Response.StatusCode = 415;
                await context.Response.WriteAsJsonAsync(new { Error = "Only application/json is accepted" });
                return;
            }
        }
        await _next(context);
    }
}

[HttpPost]
[Consumes("application/json")]
public async Task<IActionResult> CreateUser([FromBody] CreateUserRequest request)
{
    if (!ModelState.IsValid) return BadRequest(ModelState);
    var user = await _userService.CreateAsync(request);
    return CreatedAtAction(nameof(GetUser), new { id = user.Id }, user);
}
```

---

## 5. Missing Input Size Limits

### The Problem
Not limiting request sizes can lead to denial of service attacks.

### Wrong ❌
```csharp
[HttpPost("upload")]
public async Task<IActionResult> Upload(IFormFile file)
{
    using (var stream = new FileStream($"uploads/{file.FileName}", FileMode.Create))
    {
        await file.CopyToAsync(stream);
    }
    return Ok();
}
```

### Right ✅
```csharp
builder.Services.Configure<FormOptions>(options =>
{
    options.MultipartBodyLengthLimit = 10 * 1024 * 1024; // 10 MB
});

builder.Services.Configure<KestrelServerOptions>(options =>
{
    options.Limits.MaxRequestBodySize = 10 * 1024 * 1024;
});

[HttpPost("upload")]
[RequestSizeLimit(5 * 1024 * 1024)]
public async Task<IActionResult> Upload(IFormFile file)
{
    if (file == null || file.Length == 0)
        return BadRequest("No file uploaded");
    
    const long maxFileSize = 5 * 1024 * 1024;
    if (file.Length > maxFileSize)
        return BadRequest($"File size cannot exceed {maxFileSize / 1024 / 1024} MB");
    
    var allowedExtensions = new[] { ".jpg", ".png", ".pdf" };
    var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
    if (!allowedExtensions.Contains(extension))
        return BadRequest("Invalid file type");
    
    var fileName = $"{Guid.NewGuid()}{extension}";
    var filePath = Path.Combine(_uploadPath, fileName);
    
    using (var stream = new FileStream(filePath, FileMode.Create))
    {
        await file.CopyToAsync(stream);
    }
    
    return Ok(new { FileName = fileName });
}
```

---

## 6. Not Implementing CORS Properly

### The Problem
Permissive CORS policies allow unauthorized domains to access the API.

### Wrong ❌
```csharp
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", builder =>
    {
        builder.AllowAnyOrigin()
               .AllowAnyMethod()
               .AllowAnyHeader();
    });
});
```

### Right ✅
```csharp
builder.Services.AddCors(options =>
{
    options.AddPolicy("Production", builder =>
    {
        builder.WithOrigins("https://app.example.com", "https://www.example.com")
               .WithMethods("GET", "POST", "PUT", "DELETE")
               .WithHeaders("Content-Type", "Authorization")
               .AllowCredentials()
               .SetPreflightMaxAge(TimeSpan.FromMinutes(10));
    });
    
    options.AddPolicy("PublicApi", builder =>
    {
        builder.AllowAnyOrigin()
               .WithMethods("GET")
               .WithHeaders("Content-Type");
    });
});

app.UseCors(app.Environment.IsDevelopment() ? "Development" : "Production");

[ApiController]
[Route("api/public")]
[EnableCors("PublicApi")]
public class PublicApiController : ControllerBase
{
    [HttpGet("status")]
    public IActionResult GetStatus()
    {
        return Ok(new { Status = "OK", Timestamp = DateTime.UtcNow });
    }
}
```

---

## 7. Exposing Detailed Error Messages

### The Problem
Detailed error messages in production reveal system architecture and vulnerabilities.

### Wrong ❌
```csharp
[HttpGet("{id}")]
public IActionResult GetUser(int id)
{
    try
    {
        var user = _context.Users.FirstOrDefault(u => u.Id == id);
        return Ok(user);
    }
    catch (Exception ex)
    {
        return StatusCode(500, new
        {
            Error = ex.Message,
            StackTrace = ex.StackTrace
        });
    }
}
```

### Right ✅
```csharp
public class GlobalExceptionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<GlobalExceptionMiddleware> _logger;
    private readonly IHostEnvironment _environment;
    
    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing {Method} {Path}", 
                context.Request.Method, context.Request.Path);
            
            var response = new ErrorResponse
            {
                TraceId = context.TraceIdentifier,
                Message = "An error occurred processing your request"
            };
            
            context.Response.StatusCode = ex switch
            {
                NotFoundException => 404,
                UnauthorizedAccessException => 403,
                ArgumentException => 400,
                _ => 500
            };
            
            if (_environment.IsDevelopment())
            {
                response.Details = ex.Message;
                response.StackTrace = ex.StackTrace;
            }
            
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsJsonAsync(response);
        }
    }
}

public class ErrorResponse
{
    public string TraceId { get; set; }
    public string Message { get; set; }
    public string Details { get; set; }
    public string StackTrace { get; set; }
}

app.UseMiddleware<GlobalExceptionMiddleware>();
```

---

## 8. Not Logging Security Events

### The Problem
Without proper logging, security incidents go undetected and can't be investigated.

### Wrong ❌
```csharp
[HttpPost("login")]
public async Task<IActionResult> Login([FromBody] LoginRequest request)
{
    var user = await _userManager.FindByEmailAsync(request.Email);
    if (user == null || !await _userManager.CheckPasswordAsync(user, request.Password))
        return Unauthorized();
    
    return Ok(new { Token = GenerateToken(user) });
}
```

### Right ✅
```csharp
public class SecurityAuditLogger
{
    private readonly ILogger<SecurityAuditLogger> _logger;
    
    public void LogLoginAttempt(string email, string ipAddress, bool success)
    {
        _logger.LogInformation("Login attempt: {Email} from {IpAddress} - {Result}",
            email, ipAddress, success ? "Success" : "Failed");
    }
    
    public void LogUnauthorizedAccess(string userId, string resource)
    {
        _logger.LogWarning("Unauthorized access: User {UserId} tried to access {Resource}",
            userId, resource);
    }
    
    public void LogDataModification(string userId, string entity, int entityId, string action)
    {
        _logger.LogInformation("Data modification: User {UserId} {Action} {Entity} {EntityId}",
            userId, action, entity, entityId);
    }
}

[HttpPost("login")]
public async Task<IActionResult> Login([FromBody] LoginRequest request)
{
    var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
    var user = await _userManager.FindByEmailAsync(request.Email);
    
    if (user == null)
    {
        _auditLogger.LogLoginAttempt(request.Email, ipAddress, false);
        return Unauthorized(new { Message = "Invalid credentials" });
    }
    
    if (!await _userManager.CheckPasswordAsync(user, request.Password))
    {
        _auditLogger.LogLoginAttempt(request.Email, ipAddress, false);
        await _userManager.AccessFailedAsync(user);
        return Unauthorized(new { Message = "Invalid credentials" });
    }
    
    _auditLogger.LogLoginAttempt(request.Email, ipAddress, true);
    await _userManager.ResetAccessFailedCountAsync(user);
    
    return Ok(new { Token = GenerateToken(user) });
}

[HttpDelete("users/{id}")]
[Authorize(Roles = "Admin")]
public async Task<IActionResult> DeleteUser(int id)
{
    var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
    _auditLogger.LogDataModification(currentUserId, "User", id, "Delete");
    
    await _userService.DeleteAsync(id);
    return NoContent();
}
```

---

## 9. Missing API Documentation Security

### The Problem
Exposing API documentation without authentication reveals endpoints and attack surface.

### Wrong ❌
```csharp
builder.Services.AddSwaggerGen();

app.UseSwagger();
app.UseSwaggerUI(); // Publicly accessible in production!
```

### Right ✅
```csharp
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo { Title = "My API", Version = "v1" });
    
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using Bearer scheme",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });
    
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
else
{
    // Protect Swagger in production
    app.MapSwagger().RequireAuthorization("AdminOnly");
    app.UseSwaggerUI(options =>
    {
        options.SwaggerEndpoint("/swagger/v1/swagger.json", "My API V1");
    });
}
```

---

## 10. Not Implementing Request Throttling

### The Problem
Resource-intensive endpoints can be abused to cause server overload.

### Wrong ❌
```csharp
[HttpPost("process")]
public async Task<IActionResult> ProcessData([FromBody] LargeDataSet data)
{
    // No throttling - allows unlimited parallel processing
    var result = await _processor.ProcessAsync(data);
    return Ok(result);
}
```

### Right ✅
```csharp
public class ThrottleMiddleware
{
    private readonly SemaphoreSlim _semaphore;
    private readonly RequestDelegate _next;
    
    public ThrottleMiddleware(RequestDelegate next, int maxConcurrent = 10)
    {
        _next = next;
        _semaphore = new SemaphoreSlim(maxConcurrent);
    }
    
    public async Task InvokeAsync(HttpContext context)
    {
        var acquired = await _semaphore.WaitAsync(TimeSpan.FromSeconds(30));
        
        if (!acquired)
        {
            context.Response.StatusCode = 503;
            await context.Response.WriteAsJsonAsync(new
            {
                Error = "Service temporarily unavailable. Please try again later."
            });
            return;
        }
        
        try
        {
            await _next(context);
        }
        finally
        {
            _semaphore.Release();
        }
    }
}

app.UseMiddleware<ThrottleMiddleware>();

[HttpPost("process")]
[RequestTimeout(300000)] // 5 minute timeout
public async Task<IActionResult> ProcessData([FromBody] LargeDataSet data)
{
    using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(5));
    
    var result = await _processor.ProcessAsync(data, cts.Token);
    return Ok(result);
}
```

---

## Best Practices Summary

### Rate Limiting:
- Per-endpoint limits
- Distributed cache for scaling
- Proper 429 status codes
- Retry-After headers

### API Design:
- Version APIs properly
- Use DTOs, not entities
- Validate Content-Type
- Limit request sizes

### CORS:
- Whitelist origins
- Environment-specific policies
- Never AllowAnyOrigin with credentials

### Error Handling:
- Generic errors in production
- Detailed server-side logs
- Unique trace IDs
- Proper status codes

### Security:
- Log security events
- Audit data modifications
- Monitor suspicious patterns
- Protect documentation
- Implement throttling
