### Create a Webapi project

![Create a Webapi project](https://www.dropbox.com/s/cqt9o2alrimsr1j/create_webapi.jpg?raw=1 "Create a Webapi project")

### Install the required NuGet Package

```bash
Microsoft.AspNetCore.Authentication.JwtBearer
Microsoft.IdentityModel.Tokens
```
![NuGet Package Window](https://www.dropbox.com/s/ekpmcqzusya1fj9/NuGet_Packages.jpg?raw=1 "NuGet Package Window")

### appsetting.json

```json
 "Jwt": {
        "Key": "ThisismySecretKeyForCodeHackWithArun",
        "Issuer": "codehackwitharun.com"
    }
```

### Configure Authentication service in program.cs
```csharp
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Issuer"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
    };
});
```
### Add the authentication middleware in the program.cs file:

```csharp
app.UseAuthentication();
```

### Generate Token

```csharp
public static string  GenerateJSONWebToken(UserModel userInfo, IConfiguration _configuration)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(_configuration["Jwt:Issuer"],
              _configuration["Jwt:Issuer"],
              null,
              expires: DateTime.Now.AddMinutes(120),
              signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
```
_Generating a JWT in an ASP.NET Core application using the **JwtSecurityToken** class and the **JwtSecurityTokenHandler** class. The JWT is signed using a symmetric key obtained from the configuration settings, and the signature algorithm used is **HMAC** with **SHA256**._

### Consume in Controller

```csharp
        [AllowAnonymous]
        [HttpPost]
        public IActionResult Login([FromBody] UserModel login)
        {
            IActionResult response = Unauthorized();
            var user = new UserModel().AuthenticateUser(login);

            if (user != null)
            {
                var tokenString = JwtTokenHandler.GenerateJSONWebToken(user, _configuration);
                response = Ok(new { token = tokenString });
            }

            return response;
        }
```
_If the **AuthenticateUser** method returns a non-null user object, indicating that the user has been successfully authenticated, the method generates a JSON Web Token (JWT) using the **JwtTokenHandler** class and the `_configuration` object provided. The JWT contains the user's identity information and is signed with a secret key that only the server knows. The generated JWT is then returned as a part of a JSON object in the response body with a status of `Ok`._

### Perform Test in swagger

![Swagger Test](https://www.dropbox.com/s/ka1rbpf5cqaubdz/swagger-result.jpg?raw=1 "Swagger Test")

### Add the Authorization header with the JWT token to your API requests

```json
Authorization: Bearer your-jwt-token
```

### Let's Enable JWT in Swagger - Program.cs

```csharp
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Version = "v1",
        Title = "CodeHack_Jwt_authentication.api",
        Description = "Web api to provide authentication services",
    });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "Please insert JWT with Bearer into field",
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        { new OpenApiSecurityScheme {
            Reference = new OpenApiReference{Type = ReferenceType.SecurityScheme, Id = "Bearer"}}, Array.Empty<string>() }
    });
});
```

#### Add the Swagger middleware in the program.cs file:
```csharp
app.UseSwagger();
app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "CodeHack_Jwt_authentication.api"));
```
