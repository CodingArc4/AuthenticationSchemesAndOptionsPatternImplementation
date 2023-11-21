namespace AuthenticationSchemesAndOptionsPatternImplementation.OptionsSettings
{
    public class JwtSettings
    {
        public const string SectionName = "JWT";
        public string Token { get; set; } = null!;
        public string ValidIssuer { get; set; } = null!;
        public string ValidAudience { get; set; } = null!;
    }
}
