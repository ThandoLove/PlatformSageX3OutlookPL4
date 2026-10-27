using FluentValidation;
using OperationalWorkspaceApplication.DTOs;
using System;
using System.Text.RegularExpressions;

namespace OperationalWorkspaceApplication.Validators;

public class LoginRequestValidator : AbstractValidator<LoginRequestDto>
{
    // Compile and cache the Regex pattern globally with an explicit timeout to eliminate ReDoS vectors
    private static readonly Regex UsernameRegex = new Regex(
        @"^[a-zA-Z0-9_.]+$",
        RegexOptions.Compiled,
        TimeSpan.FromMilliseconds(100));

    public LoginRequestValidator()
    {
        // ==========================
        // USERNAME VALIDATION
        // ==========================
        RuleFor(x => x.Username)
            .NotEmpty().WithMessage("Username is required.")
            .MinimumLength(3).WithMessage("Username is too short.")
            .MaximumLength(50).WithMessage("Username is too long.")
            .Must(BeValidUsername).WithMessage("Username contains invalid characters.");

        // ==========================
        // PASSWORD VALIDATION
        // ==========================
        RuleFor(x => x.Password)
            .NotEmpty().WithMessage("Password is required.")
            .MinimumLength(8).WithMessage("Password must be at least 8 characters.")
            .MaximumLength(100).WithMessage("Password is too long.")
            .Must(ContainUppercase).WithMessage("Password must contain at least one uppercase letter.")
            .Must(ContainLowercase).WithMessage("Password must contain at least one lowercase letter.")
            .Must(ContainDigit).WithMessage("Password must contain at least one number.")
            .Must(NotContainSpaces).WithMessage("Password cannot contain spaces.");
    }

    // ==========================
    // USERNAME RULES
    // ==========================
    private bool BeValidUsername(string username)
    {
        if (string.IsNullOrWhiteSpace(username)) return false;

        try
        {
            return UsernameRegex.IsMatch(username);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    // ==========================
    // PASSWORD RULES
    // ==========================
    private bool ContainUppercase(string password)
        => !string.IsNullOrEmpty(password) && password.Any(char.IsUpper);

    private bool ContainLowercase(string password)
        => !string.IsNullOrEmpty(password) && password.Any(char.IsLower);

    private bool ContainDigit(string password)
        => !string.IsNullOrEmpty(password) && password.Any(char.IsDigit);

    private bool NotContainSpaces(string password)
        => !string.IsNullOrEmpty(password) && !password.Contains(" ");
}
