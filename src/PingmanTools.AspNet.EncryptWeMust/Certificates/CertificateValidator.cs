using System;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using PingmanTools.AspNet.EncryptWeMust.Certes;

namespace PingmanTools.AspNet.EncryptWeMust.Certificates
{
    public interface ICertificateValidator
    {
        bool IsCertificateValid(IAbstractCertificate certificate);
    }
    
    public class CertificateValidator : ICertificateValidator
    {
        private readonly LetsEncryptOptions _options;
        private readonly ILogger<CertificateValidator> _logger;

        public CertificateValidator(
            LetsEncryptOptions options,
            ILogger<CertificateValidator> logger)
        {
            _options = options;
            _logger = logger;
        }

        public bool IsCertificateValid(IAbstractCertificate certificate)
        {
            try
            {
                if (certificate == null)
                    return false;
                
                var now = DateTime.Now;

                _logger.LogTrace("Validating cert UntilExpiry {UntilExpiry}, AfterIssue {AfterIssue} - {Certificate}",
                    _options.TimeUntilExpiryBeforeRenewal, _options.TimeAfterIssueDateBeforeRenewal, certificate);
                    
                if (_options.TimeUntilExpiryBeforeRenewal != null && certificate.NotAfter - now < _options.TimeUntilExpiryBeforeRenewal)
                    return false;
                
                if (_options.TimeAfterIssueDateBeforeRenewal != null && now - certificate.NotBefore > _options.TimeAfterIssueDateBeforeRenewal)
                    return false;
                
                if (certificate.NotBefore > now || certificate.NotAfter < now)
                    return false;
                
                return true;
            }
            catch (CryptographicException exc)
            {
                _logger.LogError(exc, "Exception occured during certificate validation");
                return false;
            }
        }
    }
}