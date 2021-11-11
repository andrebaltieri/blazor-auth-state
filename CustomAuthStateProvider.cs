using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;

namespace BlazorJwtAuth;

public class CustomAuthStateProvider : AuthenticationStateProvider
{
    public override Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        var identity = new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.Name, "andrebaltieri"),
        }, "apiauth");

        var user = new ClaimsPrincipal(identity);

        return Task.FromResult(new AuthenticationState(user));
    }
}