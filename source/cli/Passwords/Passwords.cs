

using System;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using Microsoft.Identity.Client;

using password.vault.models;

namespace password.vault.cli
{
    public class Passwords
    {
        private readonly ILogger<Passwords> _logger;
        protected PublicAppUsingDeviceCodeFlow tokenAcquisitionHelper;
        protected ProtectedApiCallHelper<PasswordHistory> protectedApiCallHelper;
        private HttpClient client = new HttpClient();
        private string[] Scopes { get; set; }
        private string PasswordEndPoint { get; set; }
        private string PasswordApiCode { get; set; }
        private string PasswordId { get; set; }
        private string PasswordHistoryUrl { 
            get { 
                return $"{PasswordEndPoint}/api/passwords/{PasswordId}/history?code={PasswordApiCode}"; 
            }
             }
        
        public Passwords(IPublicClientApplication app, PasswordConfiguration config, ILogger<Passwords> logger)
        {
            tokenAcquisitionHelper = new PublicAppUsingDeviceCodeFlow(app, logger);
            protectedApiCallHelper = new ProtectedApiCallHelper<PasswordHistory>(client);

            this.PasswordEndPoint = config.PasswordApiEndpoint;
            this.PasswordApiCode = config.PasswordApiCode;
            this.Scopes = new string[] { config.PasswordApiScope };

            _logger = logger;
        }

        public async Task GetPasswordHistory(string id)
        {
            int x = 0;
            do{
                Console.WriteLine($"Request for token at {DateTime.Now}");
                AuthenticationResult authenticationResult = await tokenAcquisitionHelper.GetTokenForWebApi(Scopes);
                PasswordId = id;
            
                if (authenticationResult != null)
                {
                    DisplaySignedInAccount(authenticationResult.Account, authenticationResult.AccessToken);
                    var result = await CallWebApiAsync(PasswordHistoryUrl, authenticationResult.AccessToken);
                    Display(result);
                }

                TimeSpan interval = new TimeSpan(1,30,0);
                Console.WriteLine($"Sleeping for {interval.TotalSeconds} seconds");
                Thread.Sleep(interval);

                x++;
            } while(x < 2);

        }

        private void DisplaySignedInAccount(IAccount account, string token)
        {
            _logger.LogDebug($"Password Uri: {PasswordHistoryUrl}");
            _logger.LogDebug($"Logged in User: {account.Username}");
            _logger.LogDebug($"Access Token: {token}");   
        }

        private async Task<List<PasswordHistory>> CallWebApiAsync(string url, string accessToken)
        {
            var history = await protectedApiCallHelper.CallWebApiAndProcessResultAsync(url, accessToken);
            return history;
        }

        private static void Display(List<PasswordHistory> result)
        {
            Console.WriteLine("==============================================================");
            Console.WriteLine($"Password History for Site: {result.FirstOrDefault().SiteName}");
            foreach (PasswordHistory child in result.OrderByDescending(c => c.TimeStamp))
            {
                Console.WriteLine($"[{child.TimeStamp.ToString("MM/dd/yyyy hh:mm tt")}] - {child.Password}");
            }
        }
    }
}
