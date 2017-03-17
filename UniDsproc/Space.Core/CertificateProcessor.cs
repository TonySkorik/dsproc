using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Space.Core.Exceptions;
using Space.Core.Interfaces;

namespace Space.Core
{
	public class CertificateProcessor: ICertificateProcessor
	{
		public enum CertificateSource
		{
			Xml,
			Base64,
			Cer,
			Unknown
		}

		#region Get certificate

		#region [BY THUMBPRINT]
		public X509Certificate2 SearchCertificateByThumbprint(string certificateThumbprint)
		{
			try
			{
				certificateThumbprint = Regex.Replace(certificateThumbprint, @"[^\da-zA-z]", string.Empty).ToUpper();
				X509Store compStore =
					new X509Store("My", StoreLocation.LocalMachine);
				compStore.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);

				X509Store store =
					new X509Store("My", StoreLocation.CurrentUser);
				store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);

				X509Certificate2Collection found =
					compStore.Certificates.Find(
						X509FindType.FindByThumbprint,
						// X509FindType.FindBySerialNumber, 
						certificateThumbprint,
						false
					);

				if (found.Count == 0)
				{
					found = store.Certificates.Find(
						X509FindType.FindByThumbprint,
						// X509FindType.FindBySerialNumber,
						certificateThumbprint,
						false
					);
					if (found.Count != 0)
					{
						// means found in Current User store
					}
					else
					{
						throw ExceptionFactory.GetException(ExceptionType.CERTIFICATE_NOT_FOUND_BY_THUMBPRINT, certificateThumbprint);
					}
				}
				else
				{
					// means found in LocalMachine store
				}

				if (found.Count == 1)
				{
					return found[0];
				}
				else
				{
					throw ExceptionFactory.GetException(ExceptionType.MORE_THAN_ONE_CERTIFICATE, certificateThumbprint);
				}
			}
			catch (CryptographicException e)
			{
				throw ExceptionFactory.GetException(ExceptionType.UNKNOWN_CERTIFICATE_EXCEPTION, e.Message);
			}
		}

		public X509Certificate2 GetCertificateByThumbprint(
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

		#endregion

		#region [GET ALL CERTS FROM STORE]
		
		public List<X509Certificate2> GetAllCertificatesFromStore(StoreLocation storeLocation)
		{
			X509Store store = new X509Store("My", storeLocation);
			store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly | OpenFlags.MaxAllowed);
			return store.Certificates.Cast<X509Certificate2>().ToList();
		}

		#endregion

		#region [SELECT CERTIFICATE UI]
		public X509Certificate2 SelectCertificateUi(StoreLocation storeLocation) {
			X509Store store = new X509Store("MY", storeLocation);
			store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
			X509Certificate2Collection collection =
				(X509Certificate2Collection)store.Certificates;

			X509Certificate2Collection scollection =
				X509Certificate2UI.SelectFromCollection(
					collection,
					$"Выбор сертификата. Хранилище : {storeLocation.ToString()}",
					"Выберите сертификат для взаимодействия.",
					X509SelectionFlag.SingleSelection);

			return scollection.Count > 0
				? scollection[0]
				: null;
		}
		#endregion

		#endregion

		#region Read from XML

		public X509Certificate2 ReadCertificateFromXml(string signedXmlPath, string nodeId)
		{
			return ReadCertificateFromXmlDocument(XDocument.Load(signedXmlPath), nodeId);
		}

		public X509Certificate2 ReadCertificateFromXmlDocument(XDocument signedXml, string nodeId)
		{
			X509Certificate2 cert = null;
			XElement signatureElement = null;
			XNamespace ds = SignedXml.XmlDsigNamespaceUrl;

			bool isSmev2 = MessageIsSmev2Base(signedXml);

			string smev2CertRef = string.Empty;
			XNamespace wsu = Signer.WSSecurityWSUNamespaceUrl;
			XNamespace wsse = Signer.WSSecurityWSSENamespaceUrl;
			XNamespace soapenv = "http://schemas.xmlsoap.org/soap/envelope/";
			if (isSmev2 && string.IsNullOrEmpty(nodeId))
			{
				nodeId = "body";
			}

			if (string.IsNullOrEmpty(nodeId) && !isSmev2)
			{
				signatureElement = (
					from elt in signedXml.Root.Descendants()
					where elt.Name == ds + "Signature"
					select elt
				).DefaultIfEmpty(null).First();
			}
			else
			{
				try
				{
					signatureElement = (
						from elt in signedXml.Root.Descendants()
						where elt.Name == ds + "Signature"
						where elt
							.Descendants(ds + "SignedInfo").First()
							.Descendants(ds + "Reference").First()
							.Attributes("URI").First()
							.Value.Replace("#", "") == nodeId
						select elt
					).DefaultIfEmpty(null).First();
				}
				catch
				{
					throw ExceptionFactory.GetException(ExceptionType.CERTIFICATE_NOT_FOUND_BY_NODE_ID, nodeId);
				}
				if (signatureElement == null)
				{
					throw ExceptionFactory.GetException(ExceptionType.CERTIFICATE_NOT_FOUND_BY_NODE_ID, nodeId);
				}
				if (isSmev2)
				{
					smev2CertRef = signatureElement.Descendants(ds + "KeyInfo").First()
						.Descendants(wsse + "SecurityTokenReference").First()
						.Descendants(wsse + "Reference").First()
						.Attribute("URI").Value.Replace("#", "");
					if (string.IsNullOrEmpty(smev2CertRef))
					{
						throw ExceptionFactory.GetException(ExceptionType.SMEV2_CERTIFICATE_REFERENCE_NOT_FOUND);
					}
				}
			}

			if (signatureElement != null)
			{
				string certificateNodeContent = string.Empty;
				if (!isSmev2)
				{
					certificateNodeContent = (
						from node in signatureElement.Descendants()
						where node.Name == ds + "X509Certificate"
						select node.Value.ToString()
					).DefaultIfEmpty(
						//means Signature may be not named with an xmlns:ds
						(
							from node in signatureElement.Descendants()
							where node.Name == "X509Certificate"
							select node.Value.ToString()
						).DefaultIfEmpty("").First()
					).First();
				}
				else
				{
					//form smev 2
					certificateNodeContent = signedXml.Root
						.Descendants(soapenv + "Header").First()
						.Descendants(wsse + "Security")
						.Where(
							(elt) => elt.Descendants(wsse + "BinarySecurityToken").Attributes(wsu + "Id").First().Value == smev2CertRef)
						.Select((elt) => elt.Descendants(wsse + "BinarySecurityToken").First().Value).FirstOrDefault();
				}
				if (string.IsNullOrEmpty(certificateNodeContent))
				{
					// means signatureInfo appears to be empty
					throw ExceptionFactory.GetException(ExceptionType.CERTIFICATE_NOT_FOUND);
				}
				else
				{
					cert = new X509Certificate2(Convert.FromBase64String(certificateNodeContent));
				}
			}
			else
			{
				//no Signature block
				throw ExceptionFactory.GetException(ExceptionType.SIGNATURE_NOT_FOUND);
			}
			return cert;
		}
		#endregion

		#region Checks

		public bool IsCertificateExpired(X509Certificate2 cert)
		{
			if (cert == null) return true;
			DateTime dtNow = DateTime.Now.ToUniversalTime();
			return !(dtNow > cert.NotBefore.ToUniversalTime() && dtNow < cert.NotAfter.ToUniversalTime());
		}

		public bool MessageIsSmev2Base(XDocument message)
		{
			XNamespace wsse = Signer.WSSecurityWSSENamespaceUrl;
			XNamespace env = "http://schemas.xmlsoap.org/soap/envelope/";
			try
			{
				return message.Root.Descendants(env + "Header").First().Descendants(wsse + "Security").Any();
			}
			catch
			{
				return false;
			}
		}

		#endregion
	}
}
