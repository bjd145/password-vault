using System.Threading.Tasks;
using Microsoft.Identity.Client;
using Microsoft.Extensions.Logging;

namespace password.vault.cli
{
    public static class PasswordHandler 
    {
        public static async Task SendRequest( string passwordid, Microsoft.Extensions.Logging.LogLevel? logLevel ) 
        {
            var level = LoggerConfiguration.ReadFromJsonFile("appsettings.json");
            if( logLevel.HasValue ){
                level = logLevel.GetValueOrDefault();
            }
            
            ILoggerFactory loggerFactory = LoggerFactory.Create(builder =>
                builder
                    .AddFilter("Password.Vault.Cli.Passwords", level)
                    .AddConsole()
                    .AddSimpleConsole(options =>
                    {
                        options.SingleLine = true;
                        options.TimestampFormat = "hh:mm:ss ";
                    })
                
            );

            PasswordConfiguration config = PasswordConfiguration.ReadFromJsonFile("appsettings.json");

            var appConfig = config.PublicClientApplicationOptions;
            var app = PublicClientApplicationBuilder.CreateWithApplicationOptions(appConfig)
                .WithDefaultRedirectUri() 
                .Build();

            ILogger<Passwords> logger = loggerFactory.CreateLogger<Passwords>();
            Passwords p = new Passwords(app, config, logger);
            await p.GetPasswordHistory(passwordid);
        }
    }
}