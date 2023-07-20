using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;



namespace ScottBrady91.SignInWithApple.Example
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            IdentityModelEventSource.ShowPII = true;

            services.AddControllersWithViews();

             

            services.AddAuthentication(options =>
                {
                    options.DefaultScheme = "cookie";
                    options.DefaultChallengeScheme = "apple";
                })
                .AddCookie("cookie")
                .AddOpenIdConnect("apple", async options =>
                {
                    options.Authority = "https://appleid.apple.com"; // disco doc: https://appleid.apple.com/.well-known/openid-configuration

                    options.ClientId = "com.ticketersg.ticketer"; // Service ID
                    options.CallbackPath = "/signin-apple"; // corresponding to your redirect URI

                    options.ResponseType = "code id_token"; // hybrid flow due to lack of PKCE support
                    options.ResponseMode = "form_post"; // form post due to prevent PII in the URL
                    options.DisableTelemetry = true;

                    options.Scope.Clear(); // apple does not support the profile scope
                    options.Scope.Add("openid");
                    options.Scope.Add("email");
                    options.Scope.Add("name");

       

                    // custom client secret generation - secret can be re-used for up to 6 months
                    options.Events.OnAuthorizationCodeReceived = context =>
                    {
                        context.TokenEndpointRequest.ClientSecret = TokenGenerator.CreateNewToken();
                        return Task.CompletedTask;
                    };

                    options.TokenValidationParameters.ValidIssuer = "https://appleid.apple.com";
                    var jwks = await new HttpClient().GetStringAsync("https://appleid.apple.com/auth/keys");
                    options.TokenValidationParameters.IssuerSigningKeys = new JsonWebKeySet(jwks).Keys;
                    options.ProtocolValidator.RequireNonce = false;

                    options.UsePkce = false; // apple does not currently support PKCE (April 2021)
                });



   

        }

        public void Configure(IApplicationBuilder app)
        {
            app.UseDeveloperExceptionPage();

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(e => e.MapDefaultControllerRoute());
        }
    }

    public static class TokenGenerator
    {

        public static string CreateNewToken()
        {

            const string iss = "S29U8Y52XM"; // your accounts team ID found in the dev portal
            const string aud = "https://appleid.apple.com";
            const string sub = "com.ticketersg.ticketer"; // same as client_id
            var now = DateTime.UtcNow;

            //string p8path = "AuthKey_84X7X795BQ.p8";
            const string privateKeyString = "pkstring redacted";

            //using (StreamReader reader = new StreamReader(p8path))
            //{
            //    privateKeyString = reader.ReadToEnd();
            //}

            //var ecdsa = ECDsa.Create();
            //ecdsa?.ImportPkcs8PrivateKey(Convert.FromBase64String(privateKeyString), out _);

            //// Assuming you have read the P8 private key file into a string variable called privateKeyString

            //// Convert the P8 private key string into a byte array
            //byte[] privateKeyBytes = Encoding.UTF8.GetBytes(privateKeyString);

            //// Load the private key into an ECDsa object (Elliptic Curve Digital Signature Algorithm)
            //ECDsa privateKey;
            //using (ECDsaCng cryptoProvider = new ECDsaCng())
            //{
            //    cryptoProvider.ImportPkcs8PrivateKey(privateKeyBytes, out _);
            //    privateKey = cryptoProvider;
            //}

            var cngKey = CngKey.Import(
                    Convert.FromBase64String(privateKeyString),
                    CngKeyBlobFormat.Pkcs8PrivateBlob);

            var handler = new JwtSecurityTokenHandler();
             var token = handler.CreateJwtSecurityToken(
                issuer: iss,
                audience: aud,
                subject: new ClaimsIdentity(new List<Claim> { new Claim("sub", sub) }),
                expires: now.AddMonths(3), // expiry can be a maximum of 6 months
                issuedAt: now,
                notBefore: now,
                signingCredentials: new SigningCredentials(
                    new ECDsaSecurityKey(new ECDsaCng(cngKey)), SecurityAlgorithms.EcdsaSha256));

            return handler.WriteToken(token);
            //var handler = new JsonWebTokenHandler();
            //return handler.CreateToken(new SecurityTokenDescriptor
            //{
            //    Issuer = iss,
            //    Audience = aud,
            //    Claims = new Dictionary<string, object> { { "sub", sub } },
            //    Expires = now.AddMinutes(5), // expiry can be a maximum of 6 months - generate one per request or re-use until expiration
            //    IssuedAt = now,
            //    NotBefore = now,
            //    SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(new ECDsaCng(cngKey)), SecurityAlgorithms.EcdsaSha256)
            //});
        }
    }
}
