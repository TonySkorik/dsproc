using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Space.Core.Communication;
using Space.Core.Configuration;
using Space.Core.Exceptions;
using Space.Core.Interfaces;

namespace Space.Core.Processor
{
	public partial class CertificateProcessor : ICertificateProcessor
	{
		public X509Certificate2 ReadCertificateFromXml(string signedXmlPath, string nodeId)
		{
			return ReadCertificateFromXmlDocument(XDocument.Load(signedXmlPath), nodeId);
		}

		public X509Certificate2 ReadCertificateFromSignedFile(SignatureType signatureType, byte[] signedFileBytes, byte[] signatureFileBytes = null, string nodeId = null)
		{
			switch (signatureType)
			{
				case SignatureType.Smev2BaseDetached:
				case SignatureType.Smev2ChargeEnveloped:
				case SignatureType.Smev2SidebysideDetached:
				case SignatureType.Smev3BaseDetached:
				case SignatureType.Smev3SidebysideDetached:
				case SignatureType.Smev3Ack:
					var signedXmlFile = XDocument.Load(new MemoryStream(signedFileBytes));
					return ReadCertificateFromXmlDocument(signedXmlFile, nodeId);
				case SignatureType.SigDetached:
				case SignatureType.SigDetachedAllCert:
				case SignatureType.SigDetachedNoCert:
				case SignatureType.Pkcs7String:
				case SignatureType.Pkcs7StringNoCert:
				case SignatureType.Pkcs7StringAllCert:
					return ReadCertificateFromDetachedSignatureFile(signedFileBytes, signatureFileBytes);
				default:
					throw new InvalidOperationException(
						$"Signed file from signature type {signatureType} is not supported");
			}
		}

		private X509Certificate2 ReadCertificateFromDetachedSignatureFile(byte[] signedFileBytes, byte[] signatureFileBytes)
		{
			ContentInfo contentInfo = new ContentInfo(signedFileBytes);
			SignedCms signedCms = new SignedCms(contentInfo, true);
			signedCms.Decode(signatureFileBytes);

			if (signedCms.SignerInfos.Count == 0)
			{
				throw new InvalidOperationException("No signatures found in singature file");
			}

			if(signedCms.SignerInfos.Count > 1)
			{
				throw new InvalidOperationException(
					$"{signedCms.SignerInfos.Count} signatures found in singature file. Only single-signature files are supported at the moment.");
			}

			SignerInfo signerInfo = signedCms.SignerInfos[0];

			X509Certificate2 certificate = signerInfo.Certificate;

			return certificate;
		}

		public DateTime? ReadSigningDateFromSignedFile(byte[] signedFileBytes,
			byte[] signatureFileBytes)
		{
			ContentInfo contentInfo = new ContentInfo(signedFileBytes);
			SignedCms signedCms = new SignedCms(contentInfo, true);
			signedCms.Decode(signatureFileBytes);

			if (signedCms.SignerInfos.Count == 0)
			{
				return null;
			}

			if (signedCms.SignerInfos.Count > 1)
			{
				throw new InvalidOperationException(
					$"{signedCms.SignerInfos.Count} signatures found in singature file. Only single-signature files are supported at the moment.");
			}

			SignerInfo signerInfo = signedCms.SignerInfos[0];

			var signingDateTime =
				(signerInfo.SignedAttributes
					.Cast<CryptographicAttributeObject>()
					.FirstOrDefault(x => x.Oid.Value == "1.2.840.113549.1.9.5")?.Values[0] as Pkcs9SigningTime)
				?.SigningTime;

			return signingDateTime;
		}

		public X509Certificate2 ReadCertificateFromXmlDocument(XDocument signedXml, string nodeId)
		{
			if (signedXml == null)
			{
				throw new ArgumentNullException(nameof(signedXml));
			}

			X509Certificate2 cert;
			XElement signatureElement;
			XNamespace ds = SignedXml.XmlDsigNamespaceUrl;

			bool isSmev2 = MessageIsSmev2Base(signedXml);

			string smev2CertRef = string.Empty;
			XNamespace wsu = Signer.WsSecurityWsuNamespaceUrl;
			XNamespace wsse = Signer.WsSecurityWsseNamespaceUrl;
			XNamespace soapenv = "http://schemas.xmlsoap.org/soap/envelope/";

			if (isSmev2 && string.IsNullOrEmpty(nodeId))
			{
				nodeId = "body";
			}

			if (string.IsNullOrEmpty(nodeId)
				&& !isSmev2)
			{
				signatureElement = signedXml.Root.Descendants()
					.Where(elt => elt.Name == ds + "Signature")
					.DefaultIfEmpty(null)
					.First();
			}
			else
			{
				try
				{
					signatureElement = signedXml.Root.Descendants()
						.Where(elt => elt.Name == ds + "Signature")
						.Where(
							elt => elt.Descendants(ds + "SignedInfo")
								.First()
								.Descendants(ds + "Reference")
								.First()
								.Attributes("URI")
								.First()
								.Value.Substring(1) == nodeId
						)
						.DefaultIfEmpty(null)
						.First();
				}
				catch
				{
					throw ExceptionFactory.GetException(ExceptionType.CertificateNotFoundByNodeId, nodeId);
				}

				if (signatureElement == null)
				{
					throw ExceptionFactory.GetException(ExceptionType.CertificateNotFoundByNodeId, nodeId);
				}

				if (isSmev2)
				{
					smev2CertRef = signatureElement.Descendants(ds + "KeyInfo").First()
						.Descendants(wsse + "SecurityTokenReference").First()
						.Descendants(wsse + "Reference").First()
						.Attribute("URI").Value.Replace("#", "");

					if (string.IsNullOrEmpty(smev2CertRef))
					{
						throw ExceptionFactory.GetException(ExceptionType.Smev2CertificateReferenceNotFound);
					}
				}
			}

			if (signatureElement != null)
			{
				string certificateNodeContent;
				if (!isSmev2)
				{
					certificateNodeContent = (
						from node in signatureElement.Descendants()
						where node.Name == ds + "X509Certificate"
						select node.Value
					).DefaultIfEmpty(
						//means Signature may be not named with an xmlns:ds
						(
							from node in signatureElement.Descendants()
							where node.Name == "X509Certificate"
							select node.Value
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
							(elt) => elt.Descendants(wsse + "BinarySecurityToken").Attributes(wsu + "Id").First().Value
								== smev2CertRef)
						.Select((elt) => elt.Descendants(wsse + "BinarySecurityToken").First().Value).FirstOrDefault();
				}

				if (string.IsNullOrEmpty(certificateNodeContent))
				{
					// means signatureInfo appears to be empty
					throw ExceptionFactory.GetException(ExceptionType.CertificateNotFound);
				}
				else
				{
					cert = new X509Certificate2(Convert.FromBase64String(certificateNodeContent));
				}
			}
			else
			{
				//no Signature block
				throw ExceptionFactory.GetException(ExceptionType.SignatureNotFound);
			}

			return cert;
		}
	}
}
