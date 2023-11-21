namespace AuthenticationSchemesAndOptionsPatternImplementation.OptionsSettings
{
    public class JwtSettings
    {
        public const string SectionName = "JWT";
        public string Token { get; set; } = string.Empty;
        public string ValidIssuer { get; set; } = string.Empty;
        public string ValidAudience { get; set; } = string.Empty;
    }
}
