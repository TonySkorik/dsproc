using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml.Linq;
using Newtonsoft.Json;
using Formatting = System.Xml.Formatting;

namespace UniDsproc.SignatureProcessor {
	public enum StoreType {LocalMachine = 1, CurrentUser = 2}
	public static class CertificateProcessing {

		#region [SEARCH]

		#region [BY THUMBPRINT]
		public static X509Certificate2 SearchCertificateByThumbprint(string certificateThumbprint) {
			try {
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
						//						X509FindType.FindBySerialNumber, 
						certificateThumbprint,
						false
						);

				if(found.Count == 0) {
					found = store.Certificates.Find(
						X509FindType.FindByThumbprint,
						//							X509FindType.FindBySerialNumber,
						certificateThumbprint,
						false
						);
					if(found.Count != 0) {
						// means found in Current User store
					} else {
						throw new Exception($"CERT_SEARCH_EX] Certificate with thumbprint {certificateThumbprint} not found");
					}
				} else {
					// means found in LocalMachine store
				}

				if(found.Count == 1) {
					return found[0];
				} else {
					throw new Exception($"CERT_SEARC_EX] More than one certificate with thumbprint {certificateThumbprint} found!");
				}
			} catch(CryptographicException e) {
				throw new Exception($"UNKNOWN_CRYPTO_EX] Original message : {e.Message}");
			}
		}

		public static X509Certificate2 GetCertificateByThumbprint(string thumbprint, StoreLocation storeLocation) {
			X509Store compStore =
					new X509Store("My", storeLocation);
			compStore.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);

			X509Certificate2Collection found =
				compStore.Certificates.Find(
					X509FindType.FindByThumbprint,
					thumbprint,
					false
				);
			return found.Count > 0 ? found[0] : null;
		}

		#endregion

		#region [GET ALL CERTS FROM STORAGE]

		public static List<X509Certificate2> GetAllCertificatesFromStore(StoreType storeType) {
			X509Store store =
				storeType == StoreType.CurrentUser ?
				new X509Store("My", StoreLocation.CurrentUser)
				:
				new X509Store("My", StoreLocation.LocalMachine);

			store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly | OpenFlags.MaxAllowed);
			return store.Certificates.Cast<X509Certificate2>().ToList();
		}

		public static List<X509Certificate2> GetAllCertificatesFromStore(StoreLocation storeLocation) {
			X509Store store = new X509Store("My", storeLocation);
			store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly | OpenFlags.MaxAllowed);
			return store.Certificates.Cast<X509Certificate2>().ToList();
		}

		#endregion

		#endregion

		#region [READ]

		public static X509Certificate2 ReadCertificateFromXml(string signedXmlPath) {
			return ReadCertificateFromXml(XDocument.Load(signedXmlPath));
		}

		public static X509Certificate2 ReadCertificateFromXml(XDocument signedXml) {
			X509Certificate2 cert = null;

			XElement signatureElement = (
				from elt in signedXml.Root.Descendants()
				where elt.Name == (XNamespace)SignedXml.XmlDsigNamespaceUrl + "Signature"
				//where elt.Name == UnismevData.NamespaceStorage.Ns2 + "SenderInformationSystemSignature"
				select elt
			).DefaultIfEmpty(null).First();

			if(signatureElement != null) {
				string certificateNodeContent = (
					from node in signatureElement.Descendants()
					where node.Name == (XNamespace)SignedXml.XmlDsigNamespaceUrl + "X509Certificate"
					select node.Value.ToString()
					).DefaultIfEmpty(
						//means Signature may be not named with an xmlns:ds
						(
							from node in signatureElement.Descendants()
							where node.Name == "X509Certificate"
							select node.Value.ToString()
							).DefaultIfEmpty("").First()
					).First();

				if(certificateNodeContent == "") {
					throw new Exception("CERTIFICATE_NOT_FOUND] Certificate not found in passed document");
					// means signatureInfo appears to be empty
				} else {
					//cert = new X509Certificate2(Encoding.UTF8.GetBytes(certificateNodeContent));
					cert = new X509Certificate2(Convert.FromBase64String(certificateNodeContent));
				}
			} else {
				throw new Exception("NO_SIGNATURE_FOUND] Signature not found in passed document");
				//means tere is no SenderInformationSystemSignature node
				// cert = null
			}
			return cert;
		}
		#endregion

		#region [CHECK]

		public static bool IsCertificateExpired(X509Certificate2 cert) {
			if (cert == null) return true;
			DateTime dtNow = DateTime.Now.ToUniversalTime();
			return !(dtNow > cert.NotBefore.ToUniversalTime() && dtNow < cert.NotAfter.ToUniversalTime());
		}

		#endregion

		#region [TO JSON]
		public static string CertificateToJson(XDocument signedXml) {
			X509Certificate2 ci = ReadCertificateFromXml(signedXml);
			string jsonCert = null;
			if(ci != null) {
				//means cerificate present
				JsonSerializerSettings js = new JsonSerializerSettings() {
					StringEscapeHandling = StringEscapeHandling.Default
				};
				jsonCert = JsonConvert.SerializeObject(ci, Newtonsoft.Json.Formatting.Indented, js);
			}
			return jsonCert;
		}

		public static X509Certificate2 SelectCertificateUI(StoreLocation storeLocation) {
			X509Store store = new X509Store("MY", storeLocation);
			store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
			X509Certificate2Collection collection =
				(X509Certificate2Collection)store.Certificates;

			X509Certificate2Collection scollection =
				X509Certificate2UI.SelectFromCollection(collection,
				$"Выбор сертификата. Хранилище : {storeLocation.ToString()}",
				"Выберите сертификат для взаимодействия.",
				X509SelectionFlag.SingleSelection);

			return scollection.Count > 0 ? scollection[0] : null;
		}
		#endregion

	}
}
