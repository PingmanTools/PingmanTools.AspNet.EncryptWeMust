using System;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Certes;
using Certes.Acme;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NSubstitute;
using PingmanTools.AspNet.EncryptWeMust.Certes;
using PingmanTools.AspNet.EncryptWeMust.Certificates;
using PingmanTools.AspNet.EncryptWeMust.Persistence;

namespace PingmanTools.AspNet.EncryptWeMust.Tests
{
    [TestClass]
    public class LetsEncryptChallengeApprovalMiddlewareMiddlewareTests
    {
        private static readonly string AcmeToken = Guid.NewGuid().ToString();
        private static readonly  string AcmeResponse = $"{Guid.NewGuid()}-{Guid.NewGuid()}";

        private FakeLetsEncryptClient _fakeClient;
        private IHostBuilder _hostBuilder;

        [TestInitialize]
        public void Setup()
        {
            _fakeClient = new FakeLetsEncryptClient();
            var letsEncryptClientFactory = Substitute.For<ILetsEncryptClientFactory>();
            letsEncryptClientFactory.GetClient().Returns(Task.FromResult((ILetsEncryptClient)_fakeClient));

            _hostBuilder = new HostBuilder()
                .ConfigureWebHost(webBuilder =>
                {
                    webBuilder.UseTestServer();
                    webBuilder.ConfigureServices(services =>
                    {
                        services.AddLetsEncrypt(new LetsEncryptOptions()
                        {
                            Email = "some-email@github.com",
                            UseStaging = true,
                            Domains = new[] {"test.com"},
                            TimeUntilExpiryBeforeRenewal = TimeSpan.FromDays(30),
                            CertificateSigningRequest = new CsrInfo
                            {
                                CountryName = "CountryNameStuff",
                                Locality = "LocalityStuff",
                                Organization = "OrganizationStuff",
                                OrganizationUnit = "OrganizationUnitStuff",
                                State = "StateStuff"
                            }
                        });

                        services.AddLetsEncryptMemoryCertficatesPersistence();
                        services.AddLetsEncryptMemoryChallengePersistence();

                        // mock communication with LetsEncrypt
                        services.Remove(services.Single(x => x.ServiceType == typeof(ILetsEncryptClientFactory)));
                        services.AddSingleton<ILetsEncryptClientFactory>(letsEncryptClientFactory);
                    });
                    webBuilder.Configure(app =>
                    {
                        app.UseDeveloperExceptionPage();

                        app.UseLetsEncrypt();

                        app.Run(async context =>
                        {
                            context.Response.StatusCode = 404;
                            await context.Response.WriteAsync("Not found");
                        });
                    });
                })
                .ConfigureLogging(l => l.AddConsole());
        }

        [TestMethod]
        public async Task FullFlow()
        {
            using var host = await _hostBuilder.StartAsync();
            var client = host.GetTestClient();

            var initialziationTimeout = await Task.WhenAny(Task.Delay(10000, _fakeClient.OrderPlacedCts.Token));
            Assert.IsTrue(initialziationTimeout.IsCanceled, "Fake LE client initialization timed out");

            var response = await client.GetAsync($"/.well-known/acme-challenge/{AcmeToken}");

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.AreEqual(AcmeResponse, await response.Content.ReadAsStringAsync());

            var finalizationTimeout = await Task.WhenAny(Task.Delay(10000, _fakeClient.OrderFinalizedCts.Token));
            Assert.IsTrue(finalizationTimeout.IsCanceled, "Fake LE client finalization timed out");

            // Wait for the renewal service to finish setting Certificate after finalization
            for (var i = 0; i < 50 && LetsEncryptRenewalService.Certificate == null; i++)
                await Task.Delay(100);

            Assert.IsNotNull(LetsEncryptRenewalService.Certificate, "Certificate was not set after finalization");
            var appCert = ((LetsEncryptX509Certificate)LetsEncryptRenewalService.Certificate).RawData;
            var fakeCert = FakeLetsEncryptClient.FakeCert.RawData;

            Assert.IsTrue(appCert.SequenceEqual(fakeCert), "Certificates do not match");
        }

        private class FakeLetsEncryptClient : ILetsEncryptClient
        {
            public static readonly LetsEncryptX509Certificate FakeCert = SelfSignedCertificate.Make(DateTime.Now, DateTime.Now.AddDays(90));

            public CancellationTokenSource OrderPlacedCts { get; }
            public CancellationTokenSource OrderFinalizedCts { get; }

            public FakeLetsEncryptClient()
            {
                OrderPlacedCts = new CancellationTokenSource();
                OrderFinalizedCts = new CancellationTokenSource();
            }

            public async Task<PlacedOrder> PlaceOrder(string[] domains)
            {
                var challengeDtos = new []{new ChallengeDto
                {
                    Token = AcmeToken,
                    Response = AcmeResponse
                }};

                OrderPlacedCts.CancelAfter(250);

                return new PlacedOrder(
                    challengeDtos,
                    Substitute.For<IOrderContext>(),
                    Array.Empty<IChallengeContext>());
            }

            public async Task<PfxCertificate> FinalizeOrder(PlacedOrder placedOrder)
            {
                await Task.Delay(500);

                OrderFinalizedCts.CancelAfter(250);

                return new PfxCertificate(FakeCert.RawData);
            }
        }
    }
}
