using AuthenticationSchemesAndOptionsPatternImplementation.Data;
using AuthenticationSchemesAndOptionsPatternImplementation.Model;
using AuthenticationSchemesAndOptionsPatternImplementation.OptionsSettings;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;

namespace AuthenticationSchemesAndOptionsPatternImplementation
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.

            builder.Services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            //db
            builder.Services.AddDbContext<ApplicationDbContext>(options =>
            {
                options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
            });

            //idntity
            builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
                            .AddEntityFrameworkStores<ApplicationDbContext>()
                            .AddDefaultTokenProviders();

            //authentication config
            builder.Services.AddAuthentication(x =>
            {
                x.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                x.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                x.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
            .AddCookie(options => {
                options.Events.OnRedirectToLogin = (context) =>
                {
                    context.Response.StatusCode = 401;
                    return Task.CompletedTask;
                };
            })
            .AddJwtBearer(x =>
            {
                x.SaveToken = true;
                x.RequireHttpsMetadata = false;
                x.TokenValidationParameters = new TokenValidationParameters()
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidIssuer = builder.Configuration["JWT:ValidIssuer"],
                    ValidAudience = builder.Configuration["JWT:ValidAudience"],
                    IssuerSigningKey = new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(builder.Configuration["JWT:Token"]))
                };
            });

            //swagger
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen(options =>
            {
                options.SwaggerDoc("v1", new OpenApiInfo { Title = "Authentication Scheme Task -  API", Version = "v1" });
                options.AddSecurityDefinition(JwtBearerDefaults.AuthenticationScheme, new OpenApiSecurityScheme
                {
                    Name = "Authorization",
                    In = ParameterLocation.Header,
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = JwtBearerDefaults.AuthenticationScheme,
                });
                options.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
        {
                        new OpenApiSecurityScheme
                        {
                            Reference =new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id   = JwtBearerDefaults.AuthenticationScheme
                            },
                            Scheme = "Bearer",
                            Name   = JwtBearerDefaults.AuthenticationScheme,
                            In     = ParameterLocation.Header
                        },
                        new List<string>()
        }
    });
            });

            //options implementation
            builder.Services.Configure<ApplicationSettings>(
            builder.Configuration.GetSection(nameof(ApplicationSettings)));
            //builder.Services.ConfigureOptions<ApplicationSettingsSetup>();

            //jwt through options patteren
            builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection(JwtSettings.SectionName));

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI(options =>
                {
                    options.DefaultModelsExpandDepth(-1);
                });
            }

            app.UseHttpsRedirection();

            app.UseAuthorization();

            app.MapControllers();

            //using the options settings
            //Ioptions is a singleton value meaning it create an instance during the start of the application and uses that throughout
            //the lifecycle of the the app, it uses the same value bacause it caches the value.
            app.MapGet("Options",(IOptions<ApplicationSettings> options,
                IOptionsSnapshot<ApplicationSettings> optionsSnap, IOptionsMonitor<ApplicationSettings> optionsMonitor) =>
            {
                var response = new
                {
                    //configured as singleton
                    OptionsValue = options.Value.ExampleValue,
                    //configured as scoped service
                    SnapshotValue = optionsSnap.Value.ExampleValue,
                    //configured as singleton,but the current value property will always return the latest value
                    MonitorValue = optionsMonitor.CurrentValue.ExampleValue
                };

                return response;
            });

            app.Run();
        }
    }
}