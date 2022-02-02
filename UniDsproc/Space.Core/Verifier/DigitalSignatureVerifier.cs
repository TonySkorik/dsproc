using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using CryptoPro.Sharpei.Xml;
using Space.Core.Communication;
using Space.Core.Configuration;
using Space.Core.Exceptions;
using Space.Core.Extensions;
using Space.Core.Model.SignedFile;

namespace Space.Core.Verifier
{
	internal class DigitalSignatureVerifier : IVerifier
	{
		public VerifierResponse Verify(SignedXmlFile signedFile, SignatureVerificationParameters parameters)
		{
			static bool CheckChargeStructure(XmlDocument charge)
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

			var message = signedFile.GetXmlDocument();

			SignedXml signedXml = new SignedXml(message);
			Signer.Smev2SignedXml smev2SignedXml = null;

			X509Certificate2 cert = signedFile.GetCertificate();

			XmlNodeList signaturesInDoc =
				message.GetElementsByTagName(
					"Signature",
					SignedXml.XmlDsigNamespaceUrl
				);

			var signatures =
				signaturesInDoc
					.Cast<XmlElement>()
					.ToDictionary(
						(elt) =>
						{
							XNamespace ns = elt.GetXElement().Name.Namespace;
							return elt.GetXElement().Descendants(ns + "Reference").First().Attributes("URI").First()
								.Value.Replace("#", "");
						},
						(elt => elt)
					);

			if (!string.IsNullOrEmpty(signedFile.NodeId)
				&& !signatures.ContainsKey(signedFile.NodeId))
			{
				throw ExceptionFactory.GetException(ExceptionType.ReferencedSignatureNotFound, signedFile.NodeId);
			}

			if (signaturesInDoc.Count == 0)
			{
				throw ExceptionFactory.GetException(ExceptionType.NoSignaturesFound);
			}

			switch (signedFile.SignatureType)
			{
				case SignatureType.Smev2BaseDetached:
					smev2SignedXml = new Signer.Smev2SignedXml(message);
					try
					{
						smev2SignedXml.LoadXml(
							!string.IsNullOrEmpty(signedFile.NodeId)
								? signatures[signedFile.NodeId]
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

					if (!CheckChargeStructure(message))
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
						XmlDsigSmevTransform smevTransform = new XmlDsigSmevTransform();
						signedXml.SafeCanonicalizationMethods.Add(smevTransform.Algorithm);

						signedXml.LoadXml(
							!string.IsNullOrEmpty(signedFile.NodeId)
								? signatures[signedFile.NodeId]
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
						$"Detached signature verification is not supported by this method.");

				case SignatureType.Unknown:
				case SignatureType.Smev3Ack:
				case SignatureType.Rsa2048Sha256String:
				case SignatureType.RsaSha256String:
				default:
					throw ExceptionFactory.GetException(ExceptionType.UnsupportedSignatureType, signedFile.SignatureType);
			}

			var isSignatureValid = smev2SignedXml?.CheckSignature(cert.PublicKey.Key)
				??
				(cert == null
					? signedXml.CheckSignature()
					: signedXml.CheckSignature(cert, true)
				);

			var isCertificateChainValid = cert?.Verify() ?? true;

			StringBuilder verificationMessage = new();

			if (!isSignatureValid)
			{
				verificationMessage.AppendLine("Signature is invalid");
			}

			if (!isCertificateChainValid)
			{
				verificationMessage.AppendLine("Certificate chain is invalid");
			}

			var verifierResponse = new VerifierResponse()
			{
				IsCertificateChainValid = isCertificateChainValid,
				IsSignatureMathematicallyValid = isSignatureValid,
				IsSignatureSigningDateValid = true, // we do not check this for this type of signature
				Message = verificationMessage.ToString()
			};

			return verifierResponse;
		}

		public VerifierResponse Verify(SignedDetachedSignatureFile signedFile, SignatureVerificationParameters parameters)
		{
			if (signedFile.FileBytes == null)
			{
				throw new InvalidOperationException(
					"Signed file data required for detached signature verification");
			}

			if (signedFile.SignatureFileBytes == null)
			{
				throw new InvalidOperationException(
					"Signature file data required for detached signature verification");
			}

			ContentInfo contentInfo = new(signedFile.FileBytes);
			SignedCms signedCms = new(contentInfo, true);
			signedCms.Decode(signedFile.SignatureFileBytes);

			if (signedCms.SignerInfos.Count == 0)
			{
				return VerifierResponse.Invalid("No signatures found in singature file");
			}

			if (signedCms.SignerInfos.Count > 1)
			{
				return VerifierResponse.Invalid($"{signedCms.SignerInfos.Count} signatures found in singature file. Only single-signature files are supported at the moment.");
			}

			SignerInfo signerInfo = signedCms.SignerInfos[0];

			var signingDateTime =
				(signerInfo.SignedAttributes
						.Cast<CryptographicAttributeObject>()
						.FirstOrDefault(x => x.Oid.Value == "1.2.840.113549.1.9.5")?.Values[0]
					as Pkcs9SigningTime)?.SigningTime;

			signedFile.SigningDateTime = signingDateTime;

			try
			{
				signerInfo.CheckSignature(verifySignatureOnly: parameters.IsVerifyCertificateChain);
			}
			catch (CryptographicException e) 
			{
				return VerifierResponse.Invalid($"Signature is matematically invalid with message : {e.Message}");
			}

			X509Certificate2 certificate = signerInfo.Certificate;

			if (signingDateTime.HasValue)
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
	}
}
