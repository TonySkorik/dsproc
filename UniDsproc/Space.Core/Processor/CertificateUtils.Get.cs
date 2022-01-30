using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Space.Core.Exceptions;

namespace Space.Core.Processor
{
	public static partial class CertificateUtils
	{
		/// <summary>
		/// Search LocalMachine and then CurrentUser stores for the certificate with matching thumbprint
		/// </summary>
		/// <param name="certificateThumbprint">A thumbprint of the certificate to search for</param>
		/// <returns><see cref="X509Certificate2"/></returns>
		public static X509Certificate2 SearchCertificateByThumbprint(string certificateThumbprint)
		{
			try
			{
				certificateThumbprint = Regex.Replace(certificateThumbprint, @"[^\da-zA-z]", string.Empty).ToUpper();
				X509Store localMachineStore =
					new X509Store("My", StoreLocation.LocalMachine);
				localMachineStore.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);

				X509Store currentUserStore =
					new X509Store("My", StoreLocation.CurrentUser);
				currentUserStore.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);

				X509Certificate2Collection found =
					currentUserStore.Certificates.Find(
						X509FindType.FindByThumbprint,
						certificateThumbprint,
						false
					);

				if (found.Count == 0)
				{
					found = localMachineStore.Certificates.Find(
						X509FindType.FindByThumbprint,
						certificateThumbprint,
						false
					);
					if (found.Count != 0)
					{
						// means found in LocalMachine store
					}
					else
					{
						throw ExceptionFactory.GetException(
							ExceptionType.CertificateNotFoundByThumbprint,
							certificateThumbprint);
					}
				}

				if (found.Count == 1)
				{
					return found[0];
				}

				throw ExceptionFactory.GetException(ExceptionType.MoreThanOneCertificate, certificateThumbprint);
			}
			catch (CryptographicException e)
			{
				throw ExceptionFactory.GetException(ExceptionType.UnknownCertificateException, e.Message);
			}
		}

		/// <summary>
		/// Search desired location for the certificate with matching thumbprint
		/// </summary>
		/// <param name="certificateThumbprint">A thumbprint of the certificate to search for</param>
		/// <param name="storeLocation">Desired <see cref="StoreLocation"/></param>
		/// <returns><see cref="X509Certificate2"/></returns>
		public static X509Certificate2 GetCertificateByThumbprint(
			string thumbprint,
			StoreLocation storeLocation)
		{
			X509Store store =
				new X509Store("My", storeLocation);
			store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);

			X509Certificate2Collection found =
				store.Certificates.Find(
					X509FindType.FindByThumbprint,
					thumbprint,
					false
				);
			return found.Count > 0
				? found[0]
				: null;
		}

		/// <summary>
		/// Get all certificates from desired store
		/// </summary>
		/// <param name="storeLocation">Desired <see cref="StoreLocation"/></param>
		/// <returns><see cref="IEnumerable{T}"/> of <see cref="X509Certificate2"/></returns>
		public static IEnumerable<X509Certificate2> GetAllCertificatesFromStore(StoreLocation storeLocation)
		{
			X509Store store = new X509Store("My", storeLocation);
			store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly | OpenFlags.MaxAllowed);
			return store.Certificates.Cast<X509Certificate2>();
		}

		/// <summary>
		/// Shows standard Windows UI for certificate selection from desired store
		/// </summary>
		/// <param name="storeLocation">Desired <see cref="StoreLocation"/></param>
		/// <returns><see cref="X509Certificate2"/></returns>
		public static X509Certificate2 SelectCertificateUi(StoreLocation storeLocation)
		{
			X509Store store = new X509Store("MY", storeLocation);
			store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
			X509Certificate2Collection collection =
				store.Certificates;

			X509Certificate2Collection scollection =
				X509Certificate2UI.SelectFromCollection(
					collection,
					$"Выбор сертификата. Хранилище : {storeLocation}",
					"Выберите сертификат для взаимодействия.",
					X509SelectionFlag.SingleSelection);

			return scollection.Count > 0
				? scollection[0]
				: null;
		}
	}
}
