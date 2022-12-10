using IdentityManagement;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Xml;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddDataProtection();
builder.Services.AddSingleton<Database>();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme);
builder.Services.AddAuthorization(builder =>
{
    //name policy and specify policy
    builder.AddPolicy("manager", pb =>
    {
        pb.RequireAuthenticatedUser()
        .AddAuthenticationSchemes(CookieAuthenticationDefaults.AuthenticationScheme)
        .RequireClaim("role", "manager");
    });
});
builder.Services.AddSingleton<IPasswordHasher<User>, PasswordHasher<User>>();


var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseAuthentication();
app.UseAuthorization();
app.UseHttpsRedirection();

app.MapGet("/register", async (
    [FromQuery] string username,
    [FromQuery] string password,
    IPasswordHasher<User> hasher,
    Database db,
    HttpContext ctx
    ) =>
{
    var user = new User() { Username= username };
    user.PasswordHash = hasher.HashPassword(user,password);
    await db.PutAsync(user);
    await ctx.SignInAsync(
        CookieAuthenticationDefaults.AuthenticationScheme,
        UserHelper.Convert(user)
        );
    return user;
});

app.MapGet("/login", async (
    [FromQuery] string username,
    [FromQuery] string password,
    IPasswordHasher<User> hasher,
    Database db,
    HttpContext ctx
    ) =>
{
    var user = await db.GetUserAsync(username);
    var result = hasher.VerifyHashedPassword(user, user.PasswordHash, password);
    if (result == PasswordVerificationResult.Failed)
    {
        return "bad credentials";
    }
    await ctx.SignInAsync(
        CookieAuthenticationDefaults.AuthenticationScheme,
        UserHelper.Convert(user)
        );
    return "logged in";
});

app.MapGet("/promote", async (
    [FromQuery] string username,
    Database db
    ) =>
{
    var user = await db.GetUserAsync(username);
    user.Claims.Add(new UserClaim() { Type = "role", Value = "manager" });
    await db.PutAsync(user);
    return "promoted!";
});

app.MapGet("/protected", () => "top secret for the boss!!!").RequireAuthorization("manager");

app.MapGet("/start-password-reset", async (
    [FromQuery] string username,
    Database db,
    IDataProtectionProvider provider
    ) =>
{
    var protector = provider.CreateProtector("PasswordReset");
    var user = await db.GetUserAsync(username);
    //using time limit
    //var timeLimitProtector = protector.ToTimeLimitedDataProtector();
    //string protecteddata = timeLimitProtector.Protect(username, TimeSpan.FromMinutes(15));
    return protector.Protect(user.Username);
});

app.MapGet("/end-password-reset", async (
    [FromQuery] string username,
    [FromQuery] string password,
    [FromQuery] string hash,
    Database db,
    IPasswordHasher<User> hasher,
    IDataProtectionProvider provider
    ) =>
{
    var protector = provider.CreateProtector("PasswordReset");
    var hashUsername = protector.Unprotect(hash);
    if (hashUsername != username)
    {
        return "bad hash";
    }

    var user = await db.GetUserAsync(username);
    user.PasswordHash = hasher.HashPassword(user, password);
    await db.PutAsync(user);
    return "password reset";
});

app.Run();

public class UserHelper
{
    public static ClaimsPrincipal Convert(User user)
    {
        var claims = new List<Claim>()
        {
            new Claim("username",user.Username)
        };
        claims.AddRange(user.Claims.Select(x => new Claim(x.Type, x.Value)));
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        return new ClaimsPrincipal(identity);
    }
}
