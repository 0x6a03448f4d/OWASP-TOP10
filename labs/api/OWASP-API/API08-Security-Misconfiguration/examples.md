# API08: Security Misconfiguration - Code Examples

## Flask - CORS

### Vulnerable
```python
from flask_cors import CORS
CORS(app, origins='*', supports_credentials=True)  # VULNERABLE!
```

### Secure
```python
CORS(app, origins=['https://app.example.com'], supports_credentials=True)
```

## Express - Error Handling

### Vulnerable
```javascript
app.use((err, req, res, next) => {
    res.status(500).json({error: err.stack});  // Exposes stack!
});
```

### Secure
```javascript
app.use((err, req, res, next) => {
    console.error(err.stack);  // Log internally
    res.status(500).json({error: 'Internal server error'});  // Generic message
});
```

## Spring Boot - Security Headers

### Secure
```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.headers()
            .contentSecurityPolicy("default-src 'self'")
            .and()
            .frameOptions().deny()
            .xssProtection().block(true);
    }
}
```

## ASP.NET Core - CORS

### Vulnerable
```csharp
services.AddCors(options => {
    options.AddDefaultPolicy(builder => builder.AllowAnyOrigin().AllowCredentials());
});
```

### Secure
```csharp
services.AddCors(options => {
    options.AddDefaultPolicy(builder => 
        builder.WithOrigins("https://app.example.com").AllowCredentials());
});
```
