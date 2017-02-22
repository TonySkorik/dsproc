using System;
using System.Collections.Generic;
using System.Linq;
using exp = System.Linq.Expressions;
using System.Reflection;
using System.Resources;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Linq;
using UniDsproc.DataModel;

namespace UniDsproc.SignatureProcessor {
	public static class Verification {
		public enum CertificateLocation
		{
			Thumbprint = 1,
			CerFile = 2,
			Xml = 3
		}

		#region [STANDARD]
		
		public static bool VerifySignature(SignatureType mode, string documentPath, string certificateFilePath=null, string certificateThumb = null, string nodeId = null) {
			if (new List<SignatureType>{
					SignatureType.Rsa2048Sha256String,
					SignatureType.Pkcs7,
					SignatureType.Pkcs7String
				}.Contains(mode)
			)
			{
				throw new Exception(
					$"UNSUPPORTED_SIGNATURE_TYPE] Signature type <{mode}> is unsupported. Possible values are : <smev2_base.enveloped>, <smev2_charge.enveloped>, <smev2_sidebyside.detached>, <smev3_base.detached>");
			}

			XmlDocument xd = new XmlDocument();
			try {
				xd.Load(documentPath);
			} catch (Exception e) {
				throw new Exception($"INPUT_XML_MISSING_OR_CORRUPTED] Input file <{documentPath}> is invalid. Message: {e.Message}");
			}

			return VerifySignature(mode, xd, certificateFilePath, certificateThumb, nodeId);
		}

		public static bool VerifySignature(SignatureType mode, XmlDocument message, string certificateFilePath=null, string certificateThumb = null, string nodeId = null) {
			SignedXml signedXml = new SignedXml(message);
			Signing.Smev2SignedXml smev2SignedXml = null;

			X509Certificate2 cert = null;
			bool isCerFile;
			
			if ((isCerFile = !string.IsNullOrEmpty(certificateFilePath)) || !string.IsNullOrEmpty(certificateThumb)) {
				//means we are testing signature on external certificate
				if (isCerFile) {
					cert = new X509Certificate2();
					try {
						cert.Import(certificateFilePath);
					} catch (Exception e) {
						throw new Exception($"CERTIFICATE_IMPORT_EXCEPTION] Certificate <{certificateFilePath}> can not be loaded. Message: {e.Message}");
					}
				}else {
					//throws if not found
					cert = SignatureProcessor.CertificateProcessing.SearchCertificateByThumbprint(certificateThumb);
				}
			}

			Dictionary<string,XmlElement> signatures = new Dictionary<string, XmlElement>();
			
			XmlNodeList signaturesInDoc =
					message.GetElementsByTagName(
						"Signature", SignedXml.XmlDsigNamespaceUrl
						);

			signatures = 
				signaturesInDoc
				.Cast<XmlElement>()
				.ToDictionary((elt) => {
					XNamespace ns = elt.GetXElement().Name.Namespace;
					string sigRef = elt.GetXElement().Descendants(ns + "Reference").First().Attributes("URI").First().Value;
					return elt.GetXElement().Descendants(ns+"Reference").First().Attributes("URI").First().Value.Replace("#","");
				}, 
					(elt => elt)
				);

			if (!string.IsNullOrEmpty(nodeId) && !signatures.ContainsKey(nodeId)) {
				throw new Exception($"REFERENCED_SIGNATURE_NOT_FOUND] Referenced signature (-node_id=<{nodeId}>) not found in the input file.");
			}

			if (signaturesInDoc.Count < 1) {
				throw new Exception($"NO_SIGNATURES_FOUND] No signatures found in the input file.");
			}
			
			switch (mode) {
				case SignatureType.Smev2BaseDetached:
					smev2SignedXml = new Signing.Smev2SignedXml(message);
					try {
						smev2SignedXml.LoadXml(!string.IsNullOrEmpty(nodeId) ? signatures[nodeId] : signatures["body"]);
					} catch(Exception e) {
						throw new Exception($"CERTIFICATE_CONTENT_CORRUPTED] <X509Certificate> node content appears to be corrupted. Message: {e.Message}");
					}
					XmlNodeList referenceList = smev2SignedXml.KeyInfo
						.GetXml()
						.GetElementsByTagName("Reference", Signing.WSSecurityWSSENamespaceUrl);
					if(referenceList.Count == 0) {
						throw new Exception("SMEV2_CERTIFICATE_REFERENCE_NOT_FOUND] No certificate reference found in input file");
					}
					string binaryTokenReference = ((XmlElement)referenceList[0]).GetAttribute("URI");
					if(string.IsNullOrEmpty(binaryTokenReference) || binaryTokenReference[0] != '#') {
						throw new Exception("SMEV2_MALFORMED_CERTIFICATE_REFERENCE] Certificate reference appears to be malformed");
					}
					
					XmlElement binaryTokenElement = smev2SignedXml.GetIdElement(message, binaryTokenReference.Substring(1));
					if(binaryTokenElement == null) {
						throw new Exception($"SMEV2_CERTIFICATE_NOT_FOUND] Referenced certificate not found. Reference: <{binaryTokenReference.Substring(1)}>");
					}

					try {
						cert = new X509Certificate2(Convert.FromBase64String(binaryTokenElement.InnerText));
					} catch (Exception e) {
						throw new Exception($"SMEV2_CERTIFICATE_CORRUPTED] Smev2 certificate node content appears to be corrupted. Message: {e.Message}");
					}
					break;
				case SignatureType.Smev2ChargeEnveloped:
					if (signaturesInDoc.Count > 1) {
						throw new Exception($"CHARGE_TOO_MANY_SIGNATURES_FOUND] More than one signature found. Found: {signaturesInDoc.Count} sigantures.");
					}
					if (!_chargeStructureOk(message)) {
						throw new Exception($"CHARGE_MALFORMED_DOCUMENT] Document structure is malformed. <Signature> node must be either root node descendant or root node descentant descendant.");
					}

					try {
						signedXml.LoadXml(signatures.First().Value);
					} catch (Exception e) {
						throw new Exception($"CERTIFICATE_CONTENT_CORRUPTED] <X509Certificate> node content appears to be corrupted. Message: {e.Message}");
					}

					break;
				case SignatureType.Smev2SidebysideDetached:
				case SignatureType.Smev3BaseDetached:
				case SignatureType.Smev3SidebysideDetached:
					try {
						signedXml.LoadXml(!string.IsNullOrEmpty(nodeId)? signatures[nodeId]: signatures.First().Value);
					} catch(Exception e) {
						throw new Exception($"CERTIFICATE_CONTENT_CORRUPTED] <X509Certificate> node content appears to be corrupted. Message: {e.Message}");
					}
					break;
				case SignatureType.SigDetached:
				case SignatureType.Smev3Ack:
				case SignatureType.Rsa2048Sha256String: // filtered in previously called method
				case SignatureType.Pkcs7:			// filtered in previously called method
				case SignatureType.Pkcs7String:		// filtered in previously called method
					throw new Exception($"UNSUPPORTED_SIGNATURE_TYPE] Signature type <{mode}> is unsupported. Possible values are : <smev2_base.enveloped>, <smev2_charge.enveloped>, <smev2_sidebyside.detached>, <smev3_base.detached>");
			}
			
			bool result = smev2SignedXml == null?
				cert == null ? signedXml.CheckSignature() : signedXml.CheckSignature(cert, true) :
				smev2SignedXml.CheckSignature(cert.PublicKey.Key);
			
			return result;
		}

		private static bool _chargeStructureOk(XmlDocument charge) {
			XDocument x = charge.GetXDocument();
			XNamespace ds = SignedXml.XmlDsigNamespaceUrl;
			if (x.Root.Descendants(ds + "Signature").Ancestors().First().Equals(x.Root) ||
				x.Root.Descendants(ds + "Signature").Ancestors().First().Ancestors().First().Equals(x.Root)) {
				return true;
			} 
			return false;
		}

		#endregion

		#region [DS: PREFIXED] Some heavy wizardry here
		private static Type tSignedXml = typeof(SignedXml);
		private static ResourceManager SecurityResources = new ResourceManager("system.security", tSignedXml.Assembly);

		//these methods from the SignedXml class still work with prefixed Signature elements, but they are private
		private static exp.ParameterExpression thisSignedXmlParam = exp.Expression.Parameter(tSignedXml);
		private static Func<SignedXml, bool> CheckSignatureFormat
			= exp.Expression.Lambda<Func<SignedXml, bool>>(
				exp.Expression.Call(thisSignedXmlParam, tSignedXml.GetMethod("CheckSignatureFormat", BindingFlags.NonPublic | BindingFlags.Instance)),
				thisSignedXmlParam).Compile();
		private static Func<SignedXml, bool> CheckDigestedReferences
			= exp.Expression.Lambda<Func<SignedXml, bool>>(
				exp.Expression.Call(thisSignedXmlParam, tSignedXml.GetMethod("CheckDigestedReferences", BindingFlags.NonPublic | BindingFlags.Instance)),
				thisSignedXmlParam).Compile();

		public static bool CheckSignatureDs(XmlDocument xmlDoc, RSACryptoServiceProvider key) {
			if(key == null)
				throw new ArgumentNullException("key");

			SignedXml signedXml = new SignedXml(xmlDoc);

			//For XPath
			XmlNamespaceManager namespaceManager = new XmlNamespaceManager(xmlDoc.NameTable);
			namespaceManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#"); //this prefix is arbitrary and used only for XPath

			XmlElement xmlSignature = xmlDoc.SelectSingleNode("//ds:Signature", namespaceManager) as XmlElement;

			signedXml.LoadXml(xmlSignature);

			//These are the three methods called in SignedXml's CheckSignature method, but the built-in CheckSignedInfo will not validate prefixed Signature elements
			return CheckSignatureFormat(signedXml) && CheckDigestedReferences(signedXml) && CheckSignedInfo(signedXml, key);
		}

		private static bool CheckSignedInfo(SignedXml signedXml, AsymmetricAlgorithm key) {
			//Copied from reflected System.Security.Cryptography.Xml.SignedXml
			SignatureDescription signatureDescription = CryptoConfig.CreateFromName(signedXml.SignatureMethod) as SignatureDescription;
			if(signatureDescription == null)
				throw new CryptographicException(SecurityResources.GetString("Cryptography_Xml_SignatureDescriptionNotCreated"));

			Type type = Type.GetType(signatureDescription.KeyAlgorithm);
			Type type2 = key.GetType();
			if(type != type2 && !type.IsSubclassOf(type2) && !type2.IsSubclassOf(type))
				return false;

			HashAlgorithm hashAlgorithm = signatureDescription.CreateDigest();
			if(hashAlgorithm == null)
				throw new CryptographicException(SecurityResources.GetString("Cryptography_Xml_CreateHashAlgorithmFailed"));

			//Except this. The SignedXml class creates and cananicalizes a Signature element without any prefix, rather than using the element from the document provided
			byte[] c14NDigest = GetC14NDigest(signedXml, hashAlgorithm);

			AsymmetricSignatureDeformatter asymmetricSignatureDeformatter = signatureDescription.CreateDeformatter(key);
			return asymmetricSignatureDeformatter.VerifySignature(c14NDigest, signedXml.Signature.SignatureValue);
		}

		private static byte[] GetC14NDigest(SignedXml signedXml, HashAlgorithm hashAlgorithm) {
			Transform canonicalizeTransform = signedXml.SignedInfo.CanonicalizationMethodObject;
			XmlDocument xmlDoc = new XmlDocument();
			xmlDoc.LoadXml(signedXml.SignedInfo.GetXml().OuterXml);
			canonicalizeTransform.LoadInput(xmlDoc);
			return canonicalizeTransform.GetDigestedOutput(hashAlgorithm);
		}
		#endregion
	}
}
