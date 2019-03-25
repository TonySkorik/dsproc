using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Resources;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Linq;
using Space.Core.Configuration;
using Space.Core.Exceptions;
using Space.Core.Extensions;
using Space.Core.Interfaces;
using exp = System.Linq.Expressions;

namespace Space.Core {
	public class SignatureVerificator : ISignatureVerificator
	{
		#region Standard signed xml

		public bool VerifySignature(
			SignatureType mode,
			string documentPath,
			string certificateFilePath = null,
			string certificateThumb = null,
			string nodeId = null)
		{
			if (new List<SignatureType>{
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
				throw ExceptionFactory.GetException(ExceptionType.UNSUPPORTED_SIGNATURE_TYPE, mode);
			}

			XmlDocument xd = new XmlDocument();
			try
			{
				xd.Load(documentPath);
			}
			catch (Exception e)
			{
				throw ExceptionFactory.GetException(ExceptionType.INPUT_XML_MISSING_OR_CORRUPTED, documentPath, e.Message);
			}

			return VerifySignature(mode, xd, certificateFilePath, certificateThumb, nodeId);
		}

		public bool VerifySignature(
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

			if ((isCerFile = !string.IsNullOrEmpty(certificateFilePath)) || !string.IsNullOrEmpty(certificateThumb))
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
						throw ExceptionFactory.GetException(ExceptionType.CERTIFICATE_IMPORT_EXCEPTION, certificateFilePath, e.Message);
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
							string sigRef = elt.GetXElement().Descendants(ns + "Reference").First().Attributes("URI").First().Value;
							return elt.GetXElement().Descendants(ns + "Reference").First().Attributes("URI").First().Value.Replace("#", "");
						},
						(elt => elt)
					);

			if (!string.IsNullOrEmpty(nodeId) && !signatures.ContainsKey(nodeId))
			{
				throw ExceptionFactory.GetException(ExceptionType.REFERENCED_SIGNATURE_NOT_FOUND, nodeId);
			}

			if (signaturesInDoc.Count < 1)
			{
				throw ExceptionFactory.GetException(ExceptionType.NO_SIGNATURES_FOUND);
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
						throw ExceptionFactory.GetException(ExceptionType.CERTIFICATE_CONTENT_CORRUPTED, e.Message);
					}
					XmlNodeList referenceList = 
						smev2SignedXml.KeyInfo
						.GetXml()
						.GetElementsByTagName("Reference", Signer.WsSecurityWsseNamespaceUrl);
					if (referenceList.Count == 0)
					{
						throw ExceptionFactory.GetException(ExceptionType.SMEV2_CERTIFICATE_REFERENCE_NOT_FOUND);
					}
					string binaryTokenReference = ((XmlElement) referenceList[0]).GetAttribute("URI");
					if (string.IsNullOrEmpty(binaryTokenReference) || binaryTokenReference[0] != '#')
					{
						throw ExceptionFactory.GetException(ExceptionType.SMEV2_MALFORMED_CERTIFICATE_REFERENCE);
					}

					XmlElement binaryTokenElement = smev2SignedXml.GetIdElement(message, binaryTokenReference.Substring(1));
					if (binaryTokenElement == null)
					{
						throw ExceptionFactory.GetException(ExceptionType.SMEV2_CERTIFICATE_NOT_FOUND, binaryTokenReference.Substring(1));
					}

					try
					{
						cert = new X509Certificate2(Convert.FromBase64String(binaryTokenElement.InnerText));
					}
					catch (Exception e)
					{
						throw ExceptionFactory.GetException(ExceptionType.SMEV2_CERTIFICATE_CORRUPTED, e.Message);
					}
					break;
				case SignatureType.Smev2ChargeEnveloped:
					if (signaturesInDoc.Count > 1)
					{
						throw ExceptionFactory.GetException(ExceptionType.CHARGE_TOO_MANY_SIGNATURES_FOUND, signaturesInDoc.Count);
					}
					if (!ChargeStructureOk(message))
					{
						throw ExceptionFactory.GetException(ExceptionType.CHARGE_MALFORMED_DOCUMENT);
					}

					try
					{
						signedXml.LoadXml(signatures.First().Value);
					}
					catch (Exception e)
					{
						throw ExceptionFactory.GetException(ExceptionType.CERTIFICATE_CONTENT_CORRUPTED, e.Message);
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
						throw ExceptionFactory.GetException(ExceptionType.CERTIFICATE_CONTENT_CORRUPTED, e.Message);
					}
					break;
				case SignatureType.Unknown:
				case SignatureType.SigDetached:
				case SignatureType.Smev3Ack:
				case SignatureType.Rsa2048Sha256String:
				case SignatureType.RsaSha256String:
				case SignatureType.Pkcs7String:
				case SignatureType.Pkcs7StringAllCert:
				case SignatureType.Pkcs7StringNoCert:
					throw ExceptionFactory.GetException(ExceptionType.UNSUPPORTED_SIGNATURE_TYPE, mode);
				default:
					throw new ArgumentOutOfRangeException(nameof(mode), mode, null);
			}

			bool result = smev2SignedXml?.CheckSignature(cert.PublicKey.Key) ?? (cert == null
				? signedXml.CheckSignature()
				: signedXml.CheckSignature(cert, true));

			return result;
		}

		private bool ChargeStructureOk(XmlDocument charge)
		{
			XDocument x = charge.GetXDocument();
			XNamespace ds = SignedXml.XmlDsigNamespaceUrl;
			if (x.Root.Descendants(ds + "Signature").Ancestors().First().Equals(x.Root) ||
				x.Root.Descendants(ds + "Signature").Ancestors().First().Ancestors().First().Equals(x.Root))
			{
				return true;
			}
			return false;
		}

		#endregion

		#region [DS: PREFIXED DOCUMENT] Some heavy wizardry here

		private static readonly Type SignedXmlType = typeof(SignedXml);
		private static readonly ResourceManager SecurityResources = new ResourceManager("system.security", SignedXmlType.Assembly);

		//these methods from the SignedXml class still work with prefixed Signature elements, but they are private
		private static readonly exp.ParameterExpression ThisSignedXmlParam = exp.Expression.Parameter(SignedXmlType);
		private static readonly Func<SignedXml, bool> CheckSignatureFormat
			= exp.Expression.Lambda<Func<SignedXml, bool>>(
				exp.Expression.Call(
					ThisSignedXmlParam,
					SignedXmlType.GetMethod("CheckSignatureFormat", BindingFlags.NonPublic | BindingFlags.Instance)),
				ThisSignedXmlParam).Compile();
		private static readonly Func<SignedXml, bool> CheckDigestedReferences
			= exp.Expression.Lambda<Func<SignedXml, bool>>(
				exp.Expression.Call(
					ThisSignedXmlParam,
					SignedXmlType.GetMethod("CheckDigestedReferences", BindingFlags.NonPublic | BindingFlags.Instance)),
				ThisSignedXmlParam).Compile();

		public bool CheckSignatureDs(XmlDocument xmlDoc, RSACryptoServiceProvider key)
		{
			if (key == null)
				throw new ArgumentNullException(nameof(key));

			SignedXml signedXml = new SignedXml(xmlDoc);

			//For XPath
			XmlNamespaceManager namespaceManager = new XmlNamespaceManager(xmlDoc.NameTable);
			namespaceManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
				//this prefix is arbitrary and used only for XPath

			XmlElement xmlSignature = xmlDoc.SelectSingleNode("//ds:Signature", namespaceManager) as XmlElement;

			signedXml.LoadXml(xmlSignature);

			//These are the three methods called in SignedXml's CheckSignature method, but the built-in CheckSignedInfo will not validate prefixed Signature elements
			return CheckSignatureFormat(signedXml) && CheckDigestedReferences(signedXml) && CheckSignedInfo(signedXml, key);
		}

		private bool CheckSignedInfo(SignedXml signedXml, AsymmetricAlgorithm key)
		{
			//Copied from reflected System.Security.Cryptography.Xml.SignedXml
			SignatureDescription signatureDescription =
				CryptoConfig.CreateFromName(signedXml.SignatureMethod) as SignatureDescription;
			if (signatureDescription == null)
				throw new CryptographicException(SecurityResources.GetString("Cryptography_Xml_SignatureDescriptionNotCreated"));

			Type type = Type.GetType(signatureDescription.KeyAlgorithm);
			Type type2 = key.GetType();
			if (type != type2 && !type.IsSubclassOf(type2) && !type2.IsSubclassOf(type))
				return false;

			HashAlgorithm hashAlgorithm = signatureDescription.CreateDigest();
			if (hashAlgorithm == null)
				throw new CryptographicException(SecurityResources.GetString("Cryptography_Xml_CreateHashAlgorithmFailed"));

			//Except this. The SignedXml class creates and cananicalizes a Signature element without any prefix, rather than using the element from the document provided
			byte[] c14NDigest = GetC14NDigest(signedXml, hashAlgorithm);

			AsymmetricSignatureDeformatter asymmetricSignatureDeformatter = signatureDescription.CreateDeformatter(key);
			return asymmetricSignatureDeformatter.VerifySignature(c14NDigest, signedXml.Signature.SignatureValue);
		}

		private byte[] GetC14NDigest(SignedXml signedXml, HashAlgorithm hashAlgorithm)
		{
			Transform canonicalizeTransform = signedXml.SignedInfo.CanonicalizationMethodObject;
			XmlDocument xmlDoc = new XmlDocument();
			xmlDoc.LoadXml(signedXml.SignedInfo.GetXml().OuterXml);
			canonicalizeTransform.LoadInput(xmlDoc);
			return canonicalizeTransform.GetDigestedOutput(hashAlgorithm);
		}
		#endregion
	}
}
