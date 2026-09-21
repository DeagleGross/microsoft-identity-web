// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Microsoft.Identity.Web;

/// <summary>
/// Extension methods for mapping login and logout endpoints that support
/// incremental consent and Conditional Access scenarios.
/// </summary>
/// <remarks>
/// These extension methods are designed for Blazor Server scenarios to provide
/// dedicated login and logout endpoints with support for incremental consent
/// and Conditional Access. The login endpoint accepts query parameters for scopes,
/// loginHint, domainHint, and claims to enable advanced authentication scenarios.
/// Use in conjunction with <see cref="BlazorAuthenticationChallengeHandler"/> for
/// a complete authentication solution in Blazor Server applications.
/// </remarks>
public static class LoginLogoutEndpointRouteBuilderExtensions
{
    private const string CsrfProtectionTypeName =
        "Microsoft.AspNetCore.Antiforgery.ICsrfProtection, Microsoft.AspNetCore.Http.Abstractions";

    /// <summary>
    /// Maps login and logout endpoints under the current route group.
    /// The login endpoint supports incremental consent via scope, loginHint, domainHint, and claims parameters.
    /// </summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    /// <returns>The endpoint convention builder for further configuration.</returns>
    [RequiresUnreferencedCode("Minimal APIs perform reflection on delegate types which may be trimmed if not directly referenced.")]
    [RequiresDynamicCode("Minimal APIs require dynamic code generation for delegate binding.")]
    public static IEndpointConventionBuilder MapLoginAndLogout(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("");
        var useAutomaticCsrfProtection = IsAutomaticCsrfProtectionAvailable(endpoints.ServiceProvider);

        if (!useAutomaticCsrfProtection)
        {
            WarnIfAntiforgeryMissing(endpoints.ServiceProvider);
        }

        // Enhanced login endpoint that supports incremental consent and Conditional Access
        group.MapGet("/login", (
            string? returnUrl,
            string? scope,
            string? loginHint,
            string? domainHint,
            string? claims) =>
        {
            var properties = GetAuthProperties(returnUrl);

            // Add scopes if provided (for incremental consent)
            if (!string.IsNullOrEmpty(scope))
            {
                var scopes = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                properties.SetParameter(OpenIdConnectParameterNames.Scope, scopes);
            }

            // Add login hint (pre-fills username)
            if (!string.IsNullOrEmpty(loginHint))
            {
                properties.SetParameter(OpenIdConnectParameterNames.LoginHint, loginHint);
            }

            // Add domain hint (skips home realm discovery)
            if (!string.IsNullOrEmpty(domainHint))
            {
                properties.SetParameter(OpenIdConnectParameterNames.DomainHint, domainHint);
            }

            // Add claims challenge (for Conditional Access / step-up auth)
            if (!string.IsNullOrEmpty(claims))
            {
                properties.Items["claims"] = claims;
            }

            return TypedResults.Challenge(properties, [OpenIdConnectDefaults.AuthenticationScheme]);
        })
        .AllowAnonymous();

        var logoutEndpoint = group.MapPost("/logout", async (HttpContext context) =>
        {
            if (useAutomaticCsrfProtection)
            {
                var validationFeature = context.Features.Get<IAntiforgeryValidationFeature>();
                if (validationFeature is not { IsValid: true })
                {
                    return Results.BadRequest();
                }
            }
            else
            {
                // Before .NET 11, validate directly so MVC and Razor Pages hosts remain protected
                // even when they register IAntiforgery without adding UseAntiforgery middleware.
                var antiforgery = context.RequestServices.GetService<IAntiforgery>();
                if (antiforgery is not null && !await antiforgery.IsRequestValidAsync(context))
                {
                    return Results.BadRequest();
                }
            }

            string? returnUrl = null;
            if (context.Request.HasFormContentType)
            {
                var form = await context.Request.ReadFormAsync();
                returnUrl = form["ReturnUrl"];
            }

            return (IResult)TypedResults.SignOut(GetAuthProperties(returnUrl),
                [CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme]);
        })
        .RequireAuthorization();

        if (useAutomaticCsrfProtection)
        {
            // On .NET 11+, this metadata opts the endpoint into the automatically injected
            // Fetch Metadata/Origin CSRF middleware. If UseAntiforgery is also configured,
            // token validation runs later and replaces the feature with its authoritative result.
            logoutEndpoint.WithMetadata(new RequireAntiforgeryTokenAttribute());
        }

        return group;
    }

    private static bool IsAutomaticCsrfProtectionAvailable(IServiceProvider? serviceProvider)
    {
        var csrfProtectionType = Type.GetType(CsrfProtectionTypeName, throwOnError: false);
        if (csrfProtectionType is null)
        {
            return false;
        }

        var isService = serviceProvider?.GetService<IServiceProviderIsService>();
        return isService?.IsService(csrfProtectionType)
            ?? serviceProvider?.GetService(csrfProtectionType) is not null;
    }

    // Emits a single warning at endpoint-build time when IAntiforgery isn't registered in DI.
    // This surfaces the graceful-degradation state to operators so it's not silently invisible
    // that CSRF protection at /logout relies solely on RequireAuthorization + SameSite=Lax
    // (rather than token validation). Called once per MapLoginAndLogout invocation.
    private static void WarnIfAntiforgeryMissing(IServiceProvider? serviceProvider)
    {
        var isService = serviceProvider?.GetService<IServiceProviderIsService>();
        var antiforgeryRegistered = isService?.IsService(typeof(IAntiforgery)) ?? false;
        if (antiforgeryRegistered)
        {
            return;
        }

        var loggerFactory = serviceProvider?.GetService<ILoggerFactory>();
        var logger = loggerFactory?.CreateLogger(typeof(LoginLogoutEndpointRouteBuilderExtensions).FullName!);
        logger?.LogWarning(
            new EventId(1, "AntiforgeryNotRegistered"),
            "MapLoginAndLogout was called but IAntiforgery is not registered in DI. The /logout " +
            "endpoint will rely on RequireAuthorization and SameSite=Lax cookies as its CSRF gate. " +
            "To enable antiforgery token validation, call services.AddAntiforgery() (and, for " +
            "minimal APIs, app.UseAntiforgery()).");
    }

    /// <summary>
    /// Builds <see cref="AuthenticationProperties"/> with a strictly-local <c>RedirectUri</c>.
    /// Any non-local input (absolute URL, protocol-relative "//host", slash-backslash "/\host",
    /// or anything not starting with a single '/') is coerced to "/". This matches the
    /// semantics of <see cref="Microsoft.AspNetCore.Mvc.IUrlHelper.IsLocalUrl"/> and prevents
    /// open-redirect attacks via the ReturnUrl query/form parameter.
    /// </summary>
    internal static AuthenticationProperties GetAuthProperties(string? returnUrl)
    {
        const string pathBase = "/";
        return new AuthenticationProperties { RedirectUri = RedirectUriHelper.IsLocalUrl(returnUrl) ? returnUrl! : pathBase };
    }
}
