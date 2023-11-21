namespace AuthenticationSchemesAndOptionsPatternImplementation.OptionsSettings
{
    public class JwtSettings
    {
        public const string SectionName = "JWT";
        public string Token { get; init; } = null!;
        public string ValidIssuer { get; init; } = null!;
        public string ValidAudience { get; init; } = null!;
    }
}
