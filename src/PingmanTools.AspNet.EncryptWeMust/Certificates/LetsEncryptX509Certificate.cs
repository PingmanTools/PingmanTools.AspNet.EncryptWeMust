using System;
using System.Security.Cryptography.X509Certificates;

namespace PingmanTools.AspNet.EncryptWeMust.Certificates
{
    public class LetsEncryptX509Certificate : IPersistableCertificate
    {
        readonly X509Certificate2 _certificate;

        public LetsEncryptX509Certificate(X509Certificate2 certificate)
        {
            _certificate = certificate;
            RawData = certificate.Export(X509ContentType.Pfx, nameof(EncryptWeMust));
        }

        public LetsEncryptX509Certificate(byte[] data)
        {
#if NET10_0_OR_GREATER
            _certificate = X509CertificateLoader.LoadPkcs12(data, nameof(EncryptWeMust));
#else
            _certificate = new X509Certificate2(data, nameof(EncryptWeMust));
#endif
            RawData = data;
        }

        public DateTime NotAfter => _certificate.NotAfter;
        public DateTime NotBefore => _certificate.NotBefore;
        public string Thumbprint => _certificate.Thumbprint;
        public X509Certificate2 GetCertificate() => _certificate;
        public byte[] RawData { get; }

        public override string ToString()
        {
            return _certificate.ToString();
        }
    }
}