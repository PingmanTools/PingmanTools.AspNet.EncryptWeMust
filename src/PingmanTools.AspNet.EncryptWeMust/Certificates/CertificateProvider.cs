using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PingmanTools.AspNet.EncryptWeMust.Certes;
using PingmanTools.AspNet.EncryptWeMust.Persistence;

namespace PingmanTools.AspNet.EncryptWeMust.Certificates
{

    public class CertificateProvider : ICertificateProvider
    {
        private readonly IPersistenceService _persistenceService;
        private readonly ILetsEncryptClientFactory _clientFactory;
        private readonly ICertificateValidator _certificateValidator;

        private readonly ILogger<CertificateProvider> _logger;

        private readonly string[] _domains;

        public CertificateProvider(
            LetsEncryptOptions options,
            ICertificateValidator certificateValidator,
            IPersistenceService persistenceService,
            ILetsEncryptClientFactory clientFactory,
            ILogger<CertificateProvider> logger)
        {
            var domains = options.Domains?.Distinct().ToArray();
            if (domains == null || domains.Length == 0)
            {
                throw new ArgumentException("Domains configuration invalid");
            }

            _domains = domains;
            _persistenceService = persistenceService;
            _clientFactory = clientFactory;
            _certificateValidator = certificateValidator;
            _logger = logger;
        }

        public async Task<CertificateRenewalResult> RenewCertificateIfNeeded(IAbstractCertificate current = null)
        {
            _logger.LogInformation("Checking to see if in-memory LetsEncrypt certificate needs renewal.");
            if (_certificateValidator.IsCertificateValid(current))
            {
                _logger.LogInformation("Current in-memory LetsEncrypt certificate is valid.");
                return new CertificateRenewalResult(current, CertificateRenewalStatus.Unchanged);
            }
			
            _logger.LogInformation("Checking to see if existing LetsEncrypt certificate has been persisted and is valid.");
            var persistedSiteCertificate = await _persistenceService.GetPersistedSiteCertificateAsync();
            if (_certificateValidator.IsCertificateValid(persistedSiteCertificate))
            {
                _logger.LogInformation("A persisted non-expired LetsEncrypt certificate was found and will be used: {Thumbprint}", persistedSiteCertificate.Thumbprint);
                return new CertificateRenewalResult(persistedSiteCertificate, CertificateRenewalStatus.LoadedFromStore);
            }
			
            _logger.LogInformation("No valid certificate was found. Requesting new certificate from LetsEncrypt.");
            var newCertificate = await RequestNewLetsEncryptCertificate();
            return new CertificateRenewalResult(newCertificate, CertificateRenewalStatus.Renewed);
        }
        
        private async Task<IAbstractCertificate> RequestNewLetsEncryptCertificate()
        {
            var client = await _clientFactory.GetClient();

            var placedOrder = await client.PlaceOrder(_domains);

            await _persistenceService.PersistChallengesAsync(placedOrder.Challenges);

            try
            {
                var pfxCertificateBytes = await client.FinalizeOrder(placedOrder);

                await _persistenceService.PersistSiteCertificateAsync(new LetsEncryptX509Certificate(pfxCertificateBytes.Bytes));

                const string password = nameof(EncryptWeMust);
				
                return new LetsEncryptX509Certificate(pfxCertificateBytes.Bytes);
            }
            finally
            {
                await _persistenceService.DeleteChallengesAsync(placedOrder.Challenges);
            }
        }
    }
}