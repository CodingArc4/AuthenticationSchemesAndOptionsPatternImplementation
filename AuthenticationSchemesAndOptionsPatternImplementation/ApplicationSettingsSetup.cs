using Microsoft.Extensions.Options;

namespace AuthenticationSchemesAndOptionsPatternImplementation
{
    public class ApplicationSettingsSetup : IConfigureOptions<ApplicationSettings>
    {
        private readonly IConfiguration _configuration;

        public ApplicationSettingsSetup(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public void Configure(ApplicationSettings options)
        {
            _configuration.GetSection(nameof(ApplicationSettings))
                .Bind(options);
        }
    }
}
