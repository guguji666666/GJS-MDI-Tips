# List MDCA Alerts

## C code
### 1. User context get access token
```cs
using System;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;

namespace MyCSharpProject
{
    public static class MDAUtils
    {
        private const string Authority = "https://login.microsoftonline.com";
        private const string MDAId = "05a65629-4c1b-48c1-a78b-804c4abdd4af";
        private const string Scope = "Investigation.read";
        private const string ResourceUrl = "https://api.securitycenter.windows.com"; // Update with appropriate resource URL

        public static async Task<string> AcquireUserTokenAsync(string username, string password, string appId, string tenantId)
        {
            using (var httpClient = new HttpClient())
            {
                var urlEncodedBody = $"resource={ResourceUrl}&scope={MDAId}/{Scope}&client_id={appId}&grant_type=password&username={username}&password={password}";
                var stringContent = new StringContent(urlEncodedBody, Encoding.UTF8, "application/x-www-form-urlencoded");

                HttpResponseMessage response = null;
                try
                {
                    response = await httpClient.PostAsync($"{Authority}/{tenantId}/oauth2/token", stringContent).ConfigureAwait(false);
                    response.EnsureSuccessStatusCode();

                    var json = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    var jObject = JObject.Parse(json);

                    return jObject["access_token"].Value<string>();
                }
                catch (HttpRequestException ex)
                {
                    if (response != null)
                    {
                        var errorContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                        Console.WriteLine($"HTTP Request Error: {ex.Message}");
                        Console.WriteLine($"Response Status Code: {response.StatusCode}");
                        Console.WriteLine($"Response Content: {errorContent}");
                    }
                    throw;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"General Error: {ex.Message}");
                    throw;
                }
            }
        }
    }

    class Program
    {
        static async Task Main(string[] args)
        {
            // Fill these variables with your actual values
            string username = "<user account>";     // e.g., "user@example.com"
            string password = "<password>";     // e.g., "your-password"
            string appId = "<application id>";          // e.g., "abcd1234-xxxx-yyyy-zzzz-abcdefghijk"
            string tenantId = "<tenant id>";    // e.g., "12345678-xxxx-yyyy-zzzz-abcdefghijk"

            try
            {
                string token = await MDAUtils.AcquireUserTokenAsync(username, password, appId, tenantId);
                Console.WriteLine($"Access Token: {token}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred: {ex.Message}");
            }
        }
    }
}
```

