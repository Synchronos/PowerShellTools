$CertificateValidatorClass = @'
using System;
using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace CertificateValidation
{
    public class CertificateValidationResult
    {
        public string Subject { get; internal set; }
        public string Thumbprint { get; internal set; }
        public DateTime Expiration { get; internal set; }
        public DateTime ValidationTime { get; internal set; }
        public bool IsValid { get; internal set; }
        public bool Accepted { get; internal set; }
        public string Message { get; internal set; }

        public CertificateValidationResult()
        {
            ValidationTime = DateTime.UtcNow;
        }
    }

    public static class CertificateValidator
    {
        private static ConcurrentStack<CertificateValidationResult> certificateValidationResults = new ConcurrentStack<CertificateValidationResult>();

        public static CertificateValidationResult[] CertificateValidationResults
        {
            get
            {
                return certificateValidationResults.ToArray();
            }
        }

        public static CertificateValidationResult LastCertificateValidationResult
        {
            get
            {
                CertificateValidationResult lastCertificateValidationResult = null;
                certificateValidationResults.TryPeek(out lastCertificateValidationResult);

                return lastCertificateValidationResult;
            }
        }
            
        public static bool ServicePointManager_ServerCertificateValidationCallback(object sender, System.Security.Cryptography.X509Certificates.X509Certificate certificate, System.Security.Cryptography.X509Certificates.X509Chain chain, System.Net.Security.SslPolicyErrors sslPolicyErrors)
        {
            StringBuilder certificateValidationMessage = new StringBuilder();
            bool allowCertificate = true;

            if (sslPolicyErrors != System.Net.Security.SslPolicyErrors.None)
            {
                if ((sslPolicyErrors & System.Net.Security.SslPolicyErrors.RemoteCertificateNameMismatch) == System.Net.Security.SslPolicyErrors.RemoteCertificateNameMismatch)
                {
                    certificateValidationMessage.AppendFormat("The remote certificate name does not match.\r\n", certificate.Subject);
                }

                if ((sslPolicyErrors & System.Net.Security.SslPolicyErrors.RemoteCertificateChainErrors) == System.Net.Security.SslPolicyErrors.RemoteCertificateChainErrors)
                {
                    certificateValidationMessage.AppendLine("The certificate chain has the following errors:");
                    foreach (System.Security.Cryptography.X509Certificates.X509ChainStatus chainStatus in chain.ChainStatus)
                    {
                        certificateValidationMessage.AppendFormat("\t{0}", chainStatus.StatusInformation);

                        if (chainStatus.Status == System.Security.Cryptography.X509Certificates.X509ChainStatusFlags.Revoked)
                        {
                            allowCertificate = false;
                        }
                    }
                }

                if ((sslPolicyErrors & System.Net.Security.SslPolicyErrors.RemoteCertificateNotAvailable) == System.Net.Security.SslPolicyErrors.RemoteCertificateNotAvailable)
                {
                    certificateValidationMessage.AppendLine("The remote certificate was not available.");
                    allowCertificate = false;
                }

                System.Console.WriteLine();
            }
            else
            {
                certificateValidationMessage.AppendLine("The remote certificate is valid.");
            }

            CertificateValidationResult certificateValidationResult = new CertificateValidationResult
                {
                    Subject = certificate.Subject,
                    Thumbprint = certificate.GetCertHashString(),
                    Expiration = DateTime.Parse(certificate.GetExpirationDateString()),
                    IsValid = (sslPolicyErrors == System.Net.Security.SslPolicyErrors.None),
                    Accepted = allowCertificate,
                    Message = certificateValidationMessage.ToString()
                };

            certificateValidationResults.Push(certificateValidationResult);
            return allowCertificate;
        }

        public static void SetDebugCertificateValidation()
        {
            ServicePointManager.ServerCertificateValidationCallback = ServicePointManager_ServerCertificateValidationCallback;
        }

        public static void SetDefaultCertificateValidation()
        {
            ServicePointManager.ServerCertificateValidationCallback = null;
        }

        public static void ClearCertificateValidationResults()
        {
            certificateValidationResults.Clear();
        }
    }
}
'@

function Set-CertificateValidationMode
{
    <#
    .SYNOPSIS
    Sets the certificate validation mode.
    .DESCRIPTION
    Set the certificate validation mode to one of three modes with the following behaviors:
        Default -- Performs the .NET default validation of certificates. Certificates are not checked for revocation and will be rejected if invalid.
        CheckRevocationList -- Cerftificate Revocation Lists are checked and certificate will be rejected if revoked or invalid.
        Debug -- Certificate Revocation Lists are checked and revocation will result in rejection. Invalid certificates will be accepted. Certificate validation
                 information is logged and can be retrieved from the certificate handler.
    .EXAMPLE
    Set-CertificateValidationMode Debug
    .PARAMETER Mode
    The mode for certificate validation.
    #>
    [CmdletBinding(SupportsShouldProcess = $false)]
    param
    (
        [Parameter()]
        [ValidateSet('Default', 'CheckRevocationList', 'Debug')]
        [string] $Mode
    )

    begin
    {
        $isValidatorClassLoaded = (([System.AppDomain]::CurrentDomain.GetAssemblies() | ?{ $_.GlobalAssemblyCache -eq $false }) | ?{ $_.DefinedTypes.FullName -contains 'CertificateValidation.CertificateValidator' }) -ne $null

        if ($isValidatorClassLoaded -eq $false)
        {
            Add-Type -TypeDefinition $CertificateValidatorClass
        }
    }

    process
    {
        switch ($Mode)
        {
            'Debug'
            {
                [System.Net.ServicePointManager]::CheckCertificateRevocationList = $true
                [CertificateValidation.CertificateValidator]::SetDebugCertificateValidation()
            }
            'CheckRevocationList'
            {
                [System.Net.ServicePointManager]::CheckCertificateRevocationList = $true
                [CertificateValidation.CertificateValidator]::SetDefaultCertificateValidation()
            }
            'Default'
            {
                [System.Net.ServicePointManager]::CheckCertificateRevocationList = $false
                [CertificateValidation.CertificateValidator]::SetDefaultCertificateValidation()
            }
        }
    }
}

function Clear-CertificateValidationResult
{
    <#
    .SYNOPSIS
    Clears the collection of certificate validation results.
    .DESCRIPTION
    Clears the collection of certificate validation results.
    .EXAMPLE
    Get-CertificateValidationResult
    #>
    [CmdletBinding(SupportsShouldProcess = $false)]
    param()

    begin
    {
        $isValidatorClassLoaded = (([System.AppDomain]::CurrentDomain.GetAssemblies() | ?{ $_.GlobalAssemblyCache -eq $false }) | ?{ $_.DefinedTypes.FullName -contains 'CertificateValidation.CertificateValidator' }) -ne $null

        if ($isValidatorClassLoaded -eq $false)
        {
            Add-Type -TypeDefinition $CertificateValidatorClass
        }
    }

    process
    {
        [CertificateValidation.CertificateValidator]::ClearCertificateValidationResults()
        Sleep -Milliseconds 20
    }
}

function Get-CertificateValidationResult
{
    <#
    .SYNOPSIS
    Gets the certificate validation results for all operations performed in the PowerShell session since the Debug cerificate validation mode was enabled.
    .DESCRIPTION
    Gets the certificate validation results for all operations performed in the PowerShell session since the Debug certificate validation mode was enabled in reverse chronological order.
    .EXAMPLE
    Get-CertificateValidationResult
    #>
    [CmdletBinding(SupportsShouldProcess = $false)]
    param()

    begin
    {
        $isValidatorClassLoaded = (([System.AppDomain]::CurrentDomain.GetAssemblies() | ?{ $_.GlobalAssemblyCache -eq $false }) | ?{ $_.DefinedTypes.FullName -contains 'CertificateValidation.CertificateValidator' }) -ne $null

        if ($isValidatorClassLoaded -eq $false)
        {
            Add-Type -TypeDefinition $CertificateValidatorClass
        }
    }

    process
    {
        return [CertificateValidation.CertificateValidator]::CertificateValidationResults
    }
}
