# C#/.NET SQL Injection Prevention: Detailed Guide with Examples

## 1. String Concatenation in SQL Queries

### The Problem
Building SQL queries by concatenating strings allows attackers to inject arbitrary SQL code, potentially reading, modifying, or deleting any data in the database.

### Wrong ❌
```csharp
public User GetUser(string username)
{
    string query = "SELECT * FROM Users WHERE Username = '" + username + "'";
    
    using (var connection = new SqlConnection(connectionString))
    using (var command = new SqlCommand(query, connection))
    {
        connection.Open();
        var reader = command.ExecuteReader();
        // Process results...
    }
}
// Attacker sends: "admin' OR '1'='1"
// Resulting query: SELECT * FROM Users WHERE Username = 'admin' OR '1'='1'
// Returns all users!
```

### Right ✅
```csharp
public User GetUser(string username)
{
    string query = "SELECT * FROM Users WHERE Username = @Username";
    
    using (var connection = new SqlConnection(connectionString))
    using (var command = new SqlCommand(query, connection))
    {
        // Use parameterized query
        command.Parameters.AddWithValue("@Username", username);
        
        connection.Open();
        var reader = command.ExecuteReader();
        
        if (reader.Read())
        {
            return new User
            {
                Id = reader.GetInt32(0),
                Username = reader.GetString(1),
                Email = reader.GetString(2)
            };
        }
        return null;
    }
}
```

---

## 2. Dynamic SQL with Multiple Parameters

### The Problem
Even when using some parameters, combining them with string concatenation still creates injection vulnerabilities.

### Wrong ❌
```csharp
public List<Product> SearchProducts(string category, string minPrice, string maxPrice)
{
    string query = "SELECT * FROM Products WHERE Category = @Category";
    
    // Dangerous: Concatenating WHERE clauses
    if (!string.IsNullOrEmpty(minPrice))
    {
        query += " AND Price >= " + minPrice;
    }
    
    if (!string.IsNullOrEmpty(maxPrice))
    {
        query += " AND Price <= " + maxPrice;
    }
    
    using (var connection = new SqlConnection(connectionString))
    using (var command = new SqlCommand(query, connection))
    {
        command.Parameters.AddWithValue("@Category", category);
        connection.Open();
        // Execute query...
    }
}
// Attacker sends minPrice: "0 OR 1=1; DROP TABLE Products--"
```

### Right ✅
```csharp
public List<Product> SearchProducts(string category, decimal? minPrice, decimal? maxPrice)
{
    var queryBuilder = new StringBuilder("SELECT * FROM Products WHERE Category = @Category");
    
    using (var connection = new SqlConnection(connectionString))
    using (var command = new SqlCommand())
    {
        command.Connection = connection;
        command.Parameters.AddWithValue("@Category", category);
        
        // Add optional parameters safely
        if (minPrice.HasValue)
        {
            queryBuilder.Append(" AND Price >= @MinPrice");
            command.Parameters.AddWithValue("@MinPrice", minPrice.Value);
        }
        
        if (maxPrice.HasValue)
        {
            queryBuilder.Append(" AND Price <= @MaxPrice");
            command.Parameters.AddWithValue("@MaxPrice", maxPrice.Value);
        }
        
        command.CommandText = queryBuilder.ToString();
        connection.Open();
        
        var products = new List<Product>();
        using (var reader = command.ExecuteReader())
        {
            while (reader.Read())
            {
                products.Add(new Product
                {
                    Id = reader.GetInt32(0),
                    Name = reader.GetString(1),
                    Category = reader.GetString(2),
                    Price = reader.GetDecimal(3)
                });
            }
        }
        return products;
    }
}
```

---

## 3. Dynamic Table or Column Names

### The Problem
You cannot use parameters for table or column names in SQL. Building queries with user-controlled table/column names requires careful whitelisting.

### Wrong ❌
```csharp
public DataTable GetDataFromTable(string tableName, string columnName)
{
    // Parameters don't work for table/column names!
    string query = $"SELECT {columnName} FROM {tableName}";
    
    using (var connection = new SqlConnection(connectionString))
    using (var command = new SqlCommand(query, connection))
    {
        connection.Open();
        var adapter = new SqlDataAdapter(command);
        var dataTable = new DataTable();
        adapter.Fill(dataTable);
        return dataTable;
    }
}
// Attacker sends: tableName = "Users; DROP TABLE Users--"
```

### Right ✅
```csharp
public DataTable GetDataFromTable(string tableName, string columnName)
{
    // Whitelist allowed tables and columns
    var allowedTables = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "Products", "Orders", "Customers"
    };
    
    var allowedColumns = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "Id", "Name", "Description", "Price", "Category"
    };
    
    // Validate inputs against whitelist
    if (!allowedTables.Contains(tableName))
    {
        throw new ArgumentException("Invalid table name");
    }
    
    if (!allowedColumns.Contains(columnName))
    {
        throw new ArgumentException("Invalid column name");
    }
    
    // Use QUOTENAME to properly escape identifiers
    string query = $"SELECT QUOTENAME({columnName}) FROM QUOTENAME({tableName})";
    
    using (var connection = new SqlConnection(connectionString))
    using (var command = new SqlCommand(query, connection))
    {
        connection.Open();
        var adapter = new SqlDataAdapter(command);
        var dataTable = new DataTable();
        adapter.Fill(dataTable);
        return dataTable;
    }
}

// Better approach: Use a mapping dictionary
private static readonly Dictionary<string, string> TableMap = new Dictionary<string, string>
{
    ["products"] = "dbo.Products",
    ["orders"] = "dbo.Orders",
    ["customers"] = "dbo.Customers"
};

public DataTable GetDataSafely(string tableKey)
{
    if (!TableMap.TryGetValue(tableKey.ToLowerInvariant(), out string actualTableName))
    {
        throw new ArgumentException("Invalid table key");
    }
    
    string query = $"SELECT * FROM {actualTableName}";
    // Execute query...
}
```

---

## 4. Stored Procedures Called Incorrectly

### The Problem
Even stored procedures can be vulnerable if you build the call statement with string concatenation or don't use parameters.

### Wrong ❌
```csharp
public void UpdateUserEmail(int userId, string newEmail)
{
    // Don't do this!
    string query = $"EXEC UpdateEmail {userId}, '{newEmail}'";
    
    using (var connection = new SqlConnection(connectionString))
    using (var command = new SqlCommand(query, connection))
    {
        connection.Open();
        command.ExecuteNonQuery();
    }
}
// Attacker sends: newEmail = "fake@test.com'; DROP TABLE Users--"
```

### Right ✅
```csharp
public void UpdateUserEmail(int userId, string newEmail)
{
    using (var connection = new SqlConnection(connectionString))
    using (var command = new SqlCommand("UpdateEmail", connection))
    {
        // Set command type to stored procedure
        command.CommandType = CommandType.StoredProcedure;
        
        // Add parameters
        command.Parameters.AddWithValue("@UserId", userId);
        command.Parameters.AddWithValue("@NewEmail", newEmail);
        
        // Add output parameter if needed
        var result = new SqlParameter("@Result", SqlDbType.Int)
        {
            Direction = ParameterDirection.Output
        };
        command.Parameters.Add(result);
        
        connection.Open();
        command.ExecuteNonQuery();
        
        int resultValue = (int)result.Value;
        // Check result...
    }
}
```

---

## 5. Entity Framework with Raw SQL

### The Problem
Entity Framework provides protection, but using raw SQL methods incorrectly reintroduces injection vulnerabilities.

### Wrong ❌
```csharp
public List<User> SearchUsers(string searchTerm)
{
    // Vulnerable to SQL injection!
    var users = _context.Users
        .FromSqlRaw($"SELECT * FROM Users WHERE Username LIKE '%{searchTerm}%'")
        .ToList();
    
    return users;
}
```

### Right ✅
```csharp
public List<User> SearchUsers(string searchTerm)
{
    // Use parameterized raw SQL
    var users = _context.Users
        .FromSqlRaw(
            "SELECT * FROM Users WHERE Username LIKE '%' + @searchTerm + '%'",
            new SqlParameter("@searchTerm", searchTerm)
        )
        .ToList();
    
    return users;
}

// Or better: Use string interpolation (EF Core 3.0+)
public List<User> SearchUsersInterpolated(string searchTerm)
{
    // FormattableString is automatically parameterized
    var users = _context.Users
        .FromSqlInterpolated($"SELECT * FROM Users WHERE Username LIKE '%' + {searchTerm} + '%'")
        .ToList();
    
    return users;
}

// Best: Use LINQ when possible
public List<User> SearchUsersLinq(string searchTerm)
{
    var users = _context.Users
        .Where(u => u.Username.Contains(searchTerm))
        .ToList();
    
    return users;
}
```

---

## 6. LINQ Injection via Dynamic Expressions

### The Problem
Building LINQ expressions from strings can lead to injection if not handled carefully.

### Wrong ❌
```csharp
public List<Product> FilterProducts(string filterExpression)
{
    // Using Dynamic LINQ unsafely
    var products = _context.Products
        .Where(filterExpression) // Dangerous!
        .ToList();
    
    return products;
}
// Attacker could inject: "true || Price = 0"
```

### Right ✅
```csharp
public List<Product> FilterProducts(string category, decimal? minPrice, decimal? maxPrice)
{
    // Build query using safe LINQ methods
    IQueryable<Product> query = _context.Products;
    
    if (!string.IsNullOrEmpty(category))
    {
        query = query.Where(p => p.Category == category);
    }
    
    if (minPrice.HasValue)
    {
        query = query.Where(p => p.Price >= minPrice.Value);
    }
    
    if (maxPrice.HasValue)
    {
        query = query.Where(p => p.Price <= maxPrice.Value);
    }
    
    return query.ToList();
}

// If you must use Dynamic LINQ, validate heavily
public List<Product> FilterProductsSafely(string propertyName, string operatorName, object value)
{
    // Whitelist allowed properties
    var allowedProperties = new HashSet<string> { "Category", "Price", "InStock" };
    if (!allowedProperties.Contains(propertyName))
    {
        throw new ArgumentException("Invalid property");
    }
    
    // Whitelist allowed operators
    var allowedOperators = new HashSet<string> { "==", ">", "<", ">=", "<=" };
    if (!allowedOperators.Contains(operatorName))
    {
        throw new ArgumentException("Invalid operator");
    }
    
    // Build expression safely
    var parameter = Expression.Parameter(typeof(Product), "p");
    var property = Expression.Property(parameter, propertyName);
    var constant = Expression.Constant(value);
    
    Expression comparison = operatorName switch
    {
        "==" => Expression.Equal(property, constant),
        ">" => Expression.GreaterThan(property, constant),
        "<" => Expression.LessThan(property, constant),
        ">=" => Expression.GreaterThanOrEqual(property, constant),
        "<=" => Expression.LessThanOrEqual(property, constant),
        _ => throw new ArgumentException("Invalid operator")
    };
    
    var lambda = Expression.Lambda<Func<Product, bool>>(comparison, parameter);
    return _context.Products.Where(lambda).ToList();
}
```

---

## 7. ORDER BY Injection

### The Problem
Dynamic ORDER BY clauses are a common injection point because column names can't be parameterized.

### Wrong ❌
```csharp
public List<Product> GetProductsSorted(string sortColumn, string sortDirection)
{
    string query = $"SELECT * FROM Products ORDER BY {sortColumn} {sortDirection}";
    
    using (var connection = new SqlConnection(connectionString))
    using (var command = new SqlCommand(query, connection))
    {
        connection.Open();
        // Execute...
    }
}
// Attacker sends: sortColumn = "Price; DROP TABLE Products--"
```

### Right ✅
```csharp
public List<Product> GetProductsSorted(string sortColumn, string sortDirection)
{
    // Whitelist allowed columns
    var allowedColumns = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["name"] = "Name",
        ["price"] = "Price",
        ["category"] = "Category",
        ["stock"] = "StockQuantity"
    };
    
    // Whitelist allowed directions
    var allowedDirections = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "ASC", "DESC"
    };
    
    // Validate inputs
    if (!allowedColumns.TryGetValue(sortColumn, out string actualColumn))
    {
        actualColumn = "Name"; // Default
    }
    
    if (!allowedDirections.Contains(sortDirection))
    {
        sortDirection = "ASC"; // Default
    }
    
    string query = $"SELECT * FROM Products ORDER BY {actualColumn} {sortDirection}";
    
    using (var connection = new SqlConnection(connectionString))
    using (var command = new SqlCommand(query, connection))
    {
        connection.Open();
        // Execute...
    }
}

// Entity Framework approach
public List<Product> GetProductsSortedEF(string sortColumn, bool ascending)
{
    IQueryable<Product> query = _context.Products;
    
    // Use switch expression for type-safe sorting
    query = sortColumn.ToLowerInvariant() switch
    {
        "name" => ascending ? query.OrderBy(p => p.Name) : query.OrderByDescending(p => p.Name),
        "price" => ascending ? query.OrderBy(p => p.Price) : query.OrderByDescending(p => p.Price),
        "category" => ascending ? query.OrderBy(p => p.Category) : query.OrderByDescending(p => p.Category),
        _ => query.OrderBy(p => p.Name) // Default
    };
    
    return query.ToList();
}
```

---

## 8. LIKE Clause Injection

### The Problem
Even with parameterized queries, LIKE clauses need special attention to prevent injection through wildcard characters.

### Wrong ❌
```csharp
public List<User> SearchUsernames(string searchTerm)
{
    string query = "SELECT * FROM Users WHERE Username LIKE @SearchTerm";
    
    using (var connection = new SqlConnection(connectionString))
    using (var command = new SqlCommand(query, connection))
    {
        // Vulnerable: Wildcards in user input
        command.Parameters.AddWithValue("@SearchTerm", "%" + searchTerm + "%");
        connection.Open();
        // Execute...
    }
}
// Attacker sends: searchTerm = "%' OR '1'='1' --"
// While SQL injection is prevented, attacker can still use wildcards maliciously
```

### Right ✅
```csharp
public List<User> SearchUsernames(string searchTerm)
{
    // Escape special LIKE characters
    string escapedTerm = EscapeLikeValue(searchTerm);
    
    string query = @"SELECT * FROM Users 
                     WHERE Username LIKE @SearchTerm ESCAPE '\'";
    
    using (var connection = new SqlConnection(connectionString))
    using (var command = new SqlCommand(query, connection))
    {
        command.Parameters.AddWithValue("@SearchTerm", "%" + escapedTerm + "%");
        connection.Open();
        
        var users = new List<User>();
        using (var reader = command.ExecuteReader())
        {
            while (reader.Read())
            {
                users.Add(new User
                {
                    Id = reader.GetInt32(0),
                    Username = reader.GetString(1)
                });
            }
        }
        return users;
    }
}

private string EscapeLikeValue(string value)
{
    if (string.IsNullOrEmpty(value)) return value;
    
    return value
        .Replace("\\", "\\\\") // Escape the escape character
        .Replace("%", "\\%")    // Escape wildcard
        .Replace("_", "\\_")    // Escape single-character wildcard
        .Replace("[", "\\[");   // Escape bracket
}

// Entity Framework approach with validation
public List<User> SearchUsernamesEF(string searchTerm)
{
    // Validate input length to prevent DoS
    if (searchTerm.Length > 50)
    {
        throw new ArgumentException("Search term too long");
    }
    
    // EF Core automatically escapes LIKE wildcards in the value
    var users = _context.Users
        .Where(u => EF.Functions.Like(u.Username, $"%{searchTerm}%"))
        .ToList();
    
    return users;
}
```

---

## 9. Batch Queries and Multiple Statements

### The Problem
Allowing multiple SQL statements in one query opens the door to stacked query injection.

### Wrong ❌
```csharp
public void ExecuteUserQuery(string query)
{
    using (var connection = new SqlConnection(connectionString))
    using (var command = new SqlCommand(query, connection))
    {
        connection.Open();
        command.ExecuteNonQuery();
    }
}
// Attacker sends: "SELECT * FROM Users; DROP TABLE Users; --"
```

### Right ✅
```csharp
public DataTable ExecuteUserQuery(string tableName)
{
    // Never allow arbitrary queries from users
    // Instead, provide specific, safe operations
    
    var allowedTables = new Dictionary<string, string>
    {
        ["users"] = "Users",
        ["products"] = "Products",
        ["orders"] = "Orders"
    };
    
    if (!allowedTables.TryGetValue(tableName.ToLowerInvariant(), out string actualTable))
    {
        throw new ArgumentException("Invalid table name");
    }
    
    // Only allow safe, predefined operations
    string query = $"SELECT * FROM {actualTable}";
    
    using (var connection = new SqlConnection(connectionString))
    using (var command = new SqlCommand(query, connection))
    {
        connection.Open();
        var adapter = new SqlDataAdapter(command);
        var dataTable = new DataTable();
        adapter.Fill(dataTable);
        return dataTable;
    }
}

// If you must allow complex queries, use a query builder with strict validation
public class SafeQueryBuilder
{
    private readonly HashSet<string> _allowedTables;
    private readonly HashSet<string> _allowedColumns;
    private string _tableName;
    private List<string> _selectedColumns = new List<string>();
    private List<(string column, object value)> _whereConditions = new List<(string, object)>();
    
    public SafeQueryBuilder(HashSet<string> allowedTables, HashSet<string> allowedColumns)
    {
        _allowedTables = allowedTables;
        _allowedColumns = allowedColumns;
    }
    
    public SafeQueryBuilder From(string tableName)
    {
        if (!_allowedTables.Contains(tableName))
            throw new ArgumentException("Table not allowed");
        
        _tableName = tableName;
        return this;
    }
    
    public SafeQueryBuilder Select(params string[] columns)
    {
        foreach (var col in columns)
        {
            if (!_allowedColumns.Contains(col))
                throw new ArgumentException($"Column not allowed: {col}");
            
            _selectedColumns.Add(col);
        }
        return this;
    }
    
    public SafeQueryBuilder Where(string column, object value)
    {
        if (!_allowedColumns.Contains(column))
            throw new ArgumentException("Column not allowed");
        
        _whereConditions.Add((column, value));
        return this;
    }
    
    public (string query, SqlParameter[] parameters) Build()
    {
        if (string.IsNullOrEmpty(_tableName))
            throw new InvalidOperationException("Table not specified");
        
        var selectClause = _selectedColumns.Any() 
            ? string.Join(", ", _selectedColumns) 
            : "*";
        
        var query = $"SELECT {selectClause} FROM {_tableName}";
        var parameters = new List<SqlParameter>();
        
        if (_whereConditions.Any())
        {
            var whereClauses = new List<string>();
            for (int i = 0; i < _whereConditions.Count; i++)
            {
                var (column, value) = _whereConditions[i];
                var paramName = $"@p{i}";
                whereClauses.Add($"{column} = {paramName}");
                parameters.Add(new SqlParameter(paramName, value));
            }
            query += " WHERE " + string.Join(" AND ", whereClauses);
        }
        
        return (query, parameters.ToArray());
    }
}
```

---

## 10. Second-Order SQL Injection

### The Problem
Data that was previously stored in the database might contain malicious SQL if it wasn't properly sanitized on input and is later used in queries without parameters.

### Wrong ❌
```csharp
// First request: Store malicious data
public void CreateUser(string username, string bio)
{
    string query = "INSERT INTO Users (Username, Bio) VALUES (@Username, @Bio)";
    
    using (var connection = new SqlConnection(connectionString))
    using (var command = new SqlCommand(query, connection))
    {
        command.Parameters.AddWithValue("@Username", username);
        command.Parameters.AddWithValue("@Bio", bio); // Stored safely
        connection.Open();
        command.ExecuteNonQuery();
    }
}

// Second request: Use stored data unsafely
public List<Post> GetUserPosts(string username)
{
    // Get user bio from database
    string userBio = GetUserBio(username);
    
    // Vulnerable: Using database content directly in query!
    string query = $"SELECT * FROM Posts WHERE Tags LIKE '%{userBio}%'";
    
    using (var connection = new SqlConnection(connectionString))
    using (var command = new SqlCommand(query, connection))
    {
        connection.Open();
        // Execute...
    }
}
// Attacker sets bio to: "'; DROP TABLE Posts; --"
```

### Right ✅
```csharp
public void CreateUser(string username, string bio)
{
    // Validate and sanitize input before storage
    if (bio.Length > 500)
        throw new ArgumentException("Bio too long");
    
    // Remove potentially dangerous characters if needed
    bio = SanitizeBio(bio);
    
    string query = "INSERT INTO Users (Username, Bio) VALUES (@Username, @Bio)";
    
    using (var connection = new SqlConnection(connectionString))
    using (var command = new SqlCommand(query, connection))
    {
        command.Parameters.AddWithValue("@Username", username);
        command.Parameters.AddWithValue("@Bio", bio);
        connection.Open();
        command.ExecuteNonQuery();
    }
}

public List<Post> GetUserPosts(string username)
{
    string userBio = GetUserBio(username);
    
    // Always use parameters, even with database content!
    string query = "SELECT * FROM Posts WHERE Tags LIKE @SearchPattern";
    
    using (var connection = new SqlConnection(connectionString))
    using (var command = new SqlCommand(query, connection))
    {
        command.Parameters.AddWithValue("@SearchPattern", $"%{EscapeLikeValue(userBio)}%");
        connection.Open();
        
        var posts = new List<Post>();
        using (var reader = command.ExecuteReader())
        {
            while (reader.Read())
            {
                posts.Add(new Post
                {
                    Id = reader.GetInt32(0),
                    Title = reader.GetString(1),
                    Content = reader.GetString(2)
                });
            }
        }
        return posts;
    }
}

private string SanitizeBio(string bio)
{
    // Remove or encode potentially dangerous characters
    // This is defense in depth - parameters are still required!
    return bio.Replace("'", "''")
              .Replace(";", "")
              .Replace("--", "")
              .Replace("/*", "")
              .Replace("*/", "")
              .Replace("xp_", "")
              .Replace("sp_", "");
}
```

---

## Best Practices Summary

### Always Do:
1. **Use parameterized queries** for all user input
2. **Validate and sanitize** all input at entry points
3. **Whitelist** table and column names if they must be dynamic
4. **Use stored procedures** with proper parameter handling
5. **Prefer ORM LINQ queries** over raw SQL when possible
6. **Escape LIKE wildcards** when using pattern matching
7. **Use least privilege** database accounts
8. **Log all database errors** for security monitoring
9. **Use prepared statements** consistently
10. **Review all raw SQL** in code reviews

### Never Do:
1. **Never concatenate** strings to build SQL queries
2. **Never trust** data from any source (even your database)
3. **Never use** dynamic SQL unless absolutely necessary
4. **Never allow** arbitrary table/column names without whitelisting
5. **Never execute** multiple statements from user input
6. **Never use** `AddWithValue()` without type validation
7. **Never assume** stored procedures are automatically safe
8. **Never ignore** SQL injection in "internal" tools
9. **Never use** string interpolation for SQL queries
10. **Never skip** input validation because "it's parameterized"

### Testing for SQL Injection:
- Use automated scanners (SQLMap, Burp Suite)
- Test with: `' OR '1'='1`, `1'; DROP TABLE--`, `admin'--`
- Test all input fields, even hidden ones
- Check API endpoints, not just web forms
- Test ORDER BY, GROUP BY, and HAVING clauses
- Verify error messages don't expose schema information
