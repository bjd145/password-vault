﻿
using Microsoft.Identity.Client;
using System;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Collections.Generic;
using password.vault.models;

namespace password.vault.cli
{
    public class Passwords
    {
        public Passwords(IPublicClientApplication app, HttpClient client, string passwordEndPoint, string passwordApiCode, string passwordAPiScope, string passwordId)
        {
            tokenAcquisitionHelper = new PublicAppUsingDeviceCodeFlow(app);
            protectedApiCallHelper = new ProtectedApiCallHelper(client);

            this.PasswordEndPoint = passwordEndPoint;
            this.PasswordApiCode = passwordApiCode;
            this.PasswordId = passwordId;
            this.Scopes = new string[] { passwordAPiScope };
        }

        protected PublicAppUsingDeviceCodeFlow tokenAcquisitionHelper;

        protected ProtectedApiCallHelper protectedApiCallHelper;

        private string[] Scopes { get; set; }

        private string PasswordEndPoint { get; set; }
        private string PasswordApiCode { get; set; }
        private string PasswordId { get; set; }
        private string PasswordHistoryUrl { get { return $"{PasswordEndPoint}/api/passwords/{PasswordId}/history?code={PasswordApiCode}"; } }

        public async Task DisplayPasswwordHistory()
        {
            AuthenticationResult authenticationResult = await tokenAcquisitionHelper.GetTokenForWebApiUsingDeviceCodeFlowAsync(Scopes);
            if (authenticationResult != null)
            {
                DisplaySignedInAccount(authenticationResult.Account, authenticationResult.AccessToken);
                await CallWebApiAndDisplayResultAsync(PasswordHistoryUrl, authenticationResult.AccessToken);
            }
        }

        private static void DisplaySignedInAccount(IAccount account, string token)
        {
            Console.WriteLine($"Logged in User: {account.Username}");
            Console.WriteLine($"Access Token: {token}");
        }

        private async Task CallWebApiAndDisplayResultAsync(string url, string accessToken)
        {
            Console.WriteLine($"Calling Uri: {url}");
            var history = await protectedApiCallHelper.CallWebApiAndProcessResultAsync(url, accessToken);
            Display(history);
        }

        private static void Display(List<PasswordHistory> result)
        {
            Console.WriteLine(Environment.NewLine);
            foreach (PasswordHistory child in result.OrderByDescending(c => c.TimeStamp))
            {
                Console.WriteLine($"[{child.TimeStamp.ToString("MM/dd/yyyy hh:mm tt")}] {child.SiteName} - {child.Password}");
            }
        }
    }
}
