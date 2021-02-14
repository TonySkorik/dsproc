using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Linq;
using Space.Core.Communication;
using Space.Core.Configuration;
using Space.Core.Exceptions;
using Space.Core.Extensions;
using Space.Core.Interfaces;

namespace Space.Core.Verifier
{
	public partial class SignatureVerifier : ISignatureVerifier
	{
		#region Standard signed xml

		public VerifierResponse VerifySignature(
			SignatureType mode,
			string documentPath,
			string certificateFilePath = null,
			string certificateThumb = null,
			string nodeId = null)
		{
			if (new List<SignatureType>
				{
					SignatureType.Rsa2048Sha256String,
					SignatureType.RsaSha256String,

					SignatureType.Pkcs7String,
					SignatureType.Pkcs7StringAllCert,
					SignatureType.Pkcs7StringNoCert,

					SignatureType.SigDetached,
					SignatureType.SigDetachedAllCert,
					SignatureType.SigDetachedNoCert
				}.Contains(mode)
			)
			{
				throw ExceptionFactory.GetException(ExceptionType.UnsupportedSignatureType, mode);
			}

			XmlDocument xd = new XmlDocument();
			try
			{
				xd.Load(documentPath);
			}
			catch (Exception e)
			{
				throw ExceptionFactory.GetException(ExceptionType.InputXmlMissingOrCorrupted, documentPath, e.Message);
			}

			return VerifySignature(mode, xd, certificateFilePath, certificateThumb, nodeId);
		}

		public VerifierResponse VerifyDetachedSignature(
			byte[] signedFileBytes,
			byte[] signatureFileBytes)
		{
			ContentInfo contentInfo = new ContentInfo(signedFileBytes);
			SignedCms signedCms = new SignedCms(contentInfo, true);
			signedCms.Decode(signatureFileBytes);

			if (signedCms.SignerInfos.Count == 0)
			{
				return VerifierResponse.Invalid("No signatures found in singature file");
			}

			// NOTE we are working only with the first signature here. If there are more of those in file - alter this logic

			SignerInfo signerInfo = signedCms.SignerInfos[0];

			var signingDateTime =
				(signerInfo.SignedAttributes
						.Cast<CryptographicAttributeObject>()
						.FirstOrDefault(x => x.Oid.Value == "1.2.840.113549.1.9.5")?.Values[0]
					as Pkcs9SigningTime)?.SigningTime;
			
			try
			{
				signerInfo.CheckSignature(verifySignatureOnly: true);
			}
			catch (CryptographicException e)
			{
				return VerifierResponse.Invalid($"Signature is matematically invalid with message : {e.Message}");
			}

			X509Certificate2 certificate = signerInfo.Certificate;

			if(signingDateTime.HasValue)
			{
				bool isSigningDateValid =
					signingDateTime.Value < certificate.NotAfter
					&& signingDateTime.Value > certificate.NotBefore;

				if (!isSigningDateValid)
				{
					return new VerifierResponse()
					{
						IsSignatureMathematicallyValid = true,
						IsSignatureSigningDateValid = false,
						Message =
							$"Signature is matematically valid but signing date {signingDateTime.Value} lies outside of certificate validity range [{certificate.NotBefore}, {certificate.NotAfter}]"
					};
				}
			}
			else
			{
				return new VerifierResponse()
				{
					IsSignatureMathematicallyValid = true,
					IsSignatureSigningDateValid = false,
					Message = "Can't extract signing DateTime. Unable to check certificate validity on signing date."
				};
			}

			return VerifierResponse.Valid;
		}

		public VerifierResponse VerifySignature(
			SignatureType mode,
			XmlDocument message,
			string certificateFilePath = null,
			string certificateThumb = null,
			string nodeId = null)
		{
			SignedXml signedXml = new SignedXml(message);
			Signer.Smev2SignedXml smev2SignedXml = null;

			X509Certificate2 cert = null;
			bool isCerFile;

			if ((isCerFile = !string.IsNullOrEmpty(certificateFilePath))
				|| !string.IsNullOrEmpty(certificateThumb))
			{
				//means we are testing signature on external certificate
				if (isCerFile)
				{
					cert = new X509Certificate2();
					try
					{
						cert.Import(certificateFilePath);
					}
					catch (Exception e)
					{
						throw ExceptionFactory.GetException(
							ExceptionType.CertificateImportException,
							certificateFilePath,
							e.Message);
					}
				}
				else
				{
					//throws if not found
					ICertificateProcessor cp = new CertificateProcessor();
					cert = cp.SearchCertificateByThumbprint(certificateThumb);
				}
			}

			Dictionary<string, XmlElement> signatures = new Dictionary<string, XmlElement>();

			XmlNodeList signaturesInDoc =
				message.GetElementsByTagName(
					"Signature",
					SignedXml.XmlDsigNamespaceUrl
				);

			signatures =
				signaturesInDoc
					.Cast<XmlElement>()
					.ToDictionary(
						(elt) =>
						{
							XNamespace ns = elt.GetXElement().Name.Namespace;
							string sigRef = elt.GetXElement().Descendants(ns + "Reference").First().Attributes("URI")
								.First().Value;
							return elt.GetXElement().Descendants(ns + "Reference").First().Attributes("URI").First()
								.Value.Replace("#", "");
						},
						(elt => elt)
					);

			if (!string.IsNullOrEmpty(nodeId)
				&& !signatures.ContainsKey(nodeId))
			{
				throw ExceptionFactory.GetException(ExceptionType.ReferencedSignatureNotFound, nodeId);
			}

			if (signaturesInDoc.Count < 1)
			{
				throw ExceptionFactory.GetException(ExceptionType.NoSignaturesFound);
			}

			switch (mode)
			{
				case SignatureType.Smev2BaseDetached:
					smev2SignedXml = new Signer.Smev2SignedXml(message);
					try
					{
						smev2SignedXml.LoadXml(
							!string.IsNullOrEmpty(nodeId)
								? signatures[nodeId]
								: signatures["body"]);
					}
					catch (Exception e)
					{
						throw ExceptionFactory.GetException(ExceptionType.CertificateContentCorrupted, e.Message);
					}

					XmlNodeList referenceList =
						smev2SignedXml.KeyInfo
							.GetXml()
							.GetElementsByTagName("Reference", Signer.WsSecurityWsseNamespaceUrl);
					if (referenceList.Count == 0)
					{
						throw ExceptionFactory.GetException(ExceptionType.Smev2CertificateReferenceNotFound);
					}

					string binaryTokenReference = ((XmlElement)referenceList[0]).GetAttribute("URI");
					if (string.IsNullOrEmpty(binaryTokenReference)
						|| binaryTokenReference[0] != '#')
					{
						throw ExceptionFactory.GetException(ExceptionType.Smev2MalformedCertificateReference);
					}

					XmlElement binaryTokenElement = smev2SignedXml.GetIdElement(
						message,
						binaryTokenReference.Substring(1));
					if (binaryTokenElement == null)
					{
						throw ExceptionFactory.GetException(
							ExceptionType.Smev2CertificateNotFound,
							binaryTokenReference.Substring(1));
					}

					try
					{
						cert = new X509Certificate2(Convert.FromBase64String(binaryTokenElement.InnerText));
					}
					catch (Exception e)
					{
						throw ExceptionFactory.GetException(ExceptionType.Smev2CertificateCorrupted, e.Message);
					}

					break;
				case SignatureType.Smev2ChargeEnveloped:
					if (signaturesInDoc.Count > 1)
					{
						throw ExceptionFactory.GetException(
							ExceptionType.ChargeTooManySignaturesFound,
							signaturesInDoc.Count);
					}

					if (!ChargeStructureOk(message))
					{
						throw ExceptionFactory.GetException(ExceptionType.ChargeMalformedDocument);
					}

					try
					{
						signedXml.LoadXml(signatures.First().Value);
					}
					catch (Exception e)
					{
						throw ExceptionFactory.GetException(ExceptionType.CertificateContentCorrupted, e.Message);
					}

					break;

				case SignatureType.Smev2SidebysideDetached:
				case SignatureType.Smev3BaseDetached:
				case SignatureType.Smev3SidebysideDetached:
					try
					{
						signedXml.LoadXml(
							!string.IsNullOrEmpty(nodeId)
								? signatures[nodeId]
								: signatures.First().Value);
					}
					catch (Exception e)
					{
						throw ExceptionFactory.GetException(ExceptionType.CertificateContentCorrupted, e.Message);
					}

					break;

				case SignatureType.Pkcs7String:
				case SignatureType.Pkcs7StringAllCert:
				case SignatureType.Pkcs7StringNoCert: 
				case SignatureType.SigDetached:
				case SignatureType.SigDetachedAllCert:
				case SignatureType.SigDetachedNoCert:
					throw new NotSupportedException(
						$"Detached signature verification is not supported by this method. Use {nameof(VerifyDetachedSignature)} method instead.");

				case SignatureType.Unknown:
				case SignatureType.Smev3Ack:
				case SignatureType.Rsa2048Sha256String:
				case SignatureType.RsaSha256String:
					throw ExceptionFactory.GetException(ExceptionType.UnsupportedSignatureType, mode);

				default:
					throw new ArgumentOutOfRangeException(nameof(mode), mode, null);
			}

			var isSignatureValid = smev2SignedXml?.CheckSignature(cert.PublicKey.Key)
				??
				(cert == null
					? signedXml.CheckSignature()
					: signedXml.CheckSignature(cert, true)
				);

			return isSignatureValid
				? VerifierResponse.Valid
				: VerifierResponse.Invalid("Signature is invalid");
		}

		private bool ChargeStructureOk(XmlDocument charge)
		{
			XDocument x = charge.GetXDocument();
			XNamespace ds = SignedXml.XmlDsigNamespaceUrl;
			if (x.Root.Descendants(ds + "Signature").Ancestors().First().Equals(x.Root)
				|| x.Root.Descendants(ds + "Signature").Ancestors().First().Ancestors().First().Equals(x.Root))
			{
				return true;
			}

			return false;
		}

		#endregion
	}
}
