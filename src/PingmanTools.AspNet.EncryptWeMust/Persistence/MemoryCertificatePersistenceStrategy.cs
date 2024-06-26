﻿using System;
using System.Threading.Tasks;
using PingmanTools.AspNet.EncryptWeMust.Certificates;

namespace PingmanTools.AspNet.EncryptWeMust.Persistence
{
	public class MemoryCertificatePersistenceStrategy : ICertificatePersistenceStrategy
	{
		IKeyCertificate _accountCertificate;
		IAbstractCertificate _siteCertificate;

		public Task PersistAsync(CertificateType persistenceType, IPersistableCertificate certificate)
		{
			switch (persistenceType)
			{
				case CertificateType.Account:
					_accountCertificate = (IKeyCertificate)certificate;
					break;
				case CertificateType.Site:
					_siteCertificate = certificate;
					break;
				default:
					throw new ArgumentException("Unhandled persistence type", nameof(persistenceType));
			}
			return Task.CompletedTask;
		}

		public Task<IKeyCertificate> RetrieveAccountCertificateAsync()
		{
			return Task.FromResult(_accountCertificate);
		}

		public Task<IAbstractCertificate> RetrieveSiteCertificateAsync()
		{
			return Task.FromResult(_siteCertificate);
		}
	}
}
