using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using exp = System.Linq.Expressions;
using System.Reflection;
using System.Resources;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using Newtonsoft.Json.Serialization;
using UniDsproc.DataModel;

namespace UniDsproc.SignatureProcessor {
	public static class Verification {
		public enum CertificateLocation {Thumbprint = 1, CerFile = 2, Xml = 3}
		public enum SignatureNodeAddressesBy {NodeId = 1, NodeName = 2, NodeNameNamespace = 3, Default = 4}


		#region [STANDARD]
		public static bool VerifySignature(string message, bool verifySignatureOnly = false) {
			XmlDocument xd = new XmlDocument();
			xd.Load(new StringReader(message));
			return _verifySignature(xd, verifySignatureOnly);
		}
		
		public static bool VerifySignature(string documentPath, string certificateFilePath=null, string certificateThumb = null, string nodeId = null) {
			XmlDocument xd = new XmlDocument();
			try {
				xd.Load(documentPath);
			} catch (Exception e) {
				throw new ArgumentNullException($"INPUT_FILE_MISSING] Input file <{documentPath}> is invalid");
			}

			return VerifySignature(xd, certificateFilePath, certificateThumb, nodeId);
		}

		public static bool VerifySignature(XmlDocument message, string certificateFilePath=null, string certificateThumb = null, string nodeId = null) {
			SignedXml signedXml = new SignedXml(message);

			X509Certificate2 cert = null;
			bool isCerFile;
			
			if ((isCerFile = !string.IsNullOrEmpty(certificateFilePath)) || !string.IsNullOrEmpty(certificateThumb)) {
				//means we are testing signature on external certificate
				if (isCerFile) {
					//cert = (X509Certificate2) X509Certificate.CreateFromCertFile(certificateFilePath);
					cert = new X509Certificate2();
					try {
						cert.Import(certificateFilePath);
					} catch (Exception e) {
						throw new ArgumentException($"CERTIFICATE_IMPOIRT_EXCEPTION] Certificate <{certificateFilePath}> can not be loaded. Message: {e.Message}");
					}
				}else {
					//throws if not found
					cert = SignatureProcessor.CertificateProcessing.SearchCertificateByThumbprint(certificateThumb);
				}
			}

			Dictionary<XElement,XmlElement> signatures = new Dictionary<XElement, XmlElement>();
			
			XmlNodeList signaturesInDoc =
					message.GetElementsByTagName(
						"Signature", SignedXml.XmlDsigNamespaceUrl
						);
			signatures = signaturesInDoc
				.Cast<XmlElement>()
				.ToDictionary((elt) => {
					XNamespace ns = elt.GetXElement().Name.Namespace;
								XElement sigRef = elt.GetXElement().Descendants(ns + "Reference").First();
					
					string refValue = elt.GetXElement().Descendants(ns+"Reference").First().Attributes("URI").First().Value;
					XDocument xd = message.GetXDocument();
					return xd.Root.Descendants().FirstOrDefault(d => d.Attribute("Id").Value == refValue);
				}, 
					(elt => elt)
				);
			//select first signature who's reference URI == #nodeId
			XmlElement signatureToVerify = null;

			/*if (string.IsNullOrEmpty(nodeId) && string.IsNullOrEmpty(nodeName)) {
				signatureToVerify = 
					signaturesInDoc
					.Cast<XmlElement>()
					.First();
				/*return signaturesInDoc
						.Cast<XmlElement>()
						.Aggregate(true,
							(current, signature) => {
								signedXml.LoadXml(signature);
								return current || cert == null ? signedXml.CheckSignature() : signedXml.CheckSignature(cert, true);
							}
						);#1#
			} else {
				if (!string.IsNullOrEmpty(nodeId)) {
					//means search signatures by nodeId
					signatureToVerify = 
						signaturesInDoc
							.Cast<XmlElement>()
							.Where((elt) => 
								elt
								.GetXElement()
								.Descendants()
								.Elements("Reference")
								.Attributes("URI")
								.First()
								.Value == "#" + nodeId)
							.Select(elt => elt)
							.First();
				} else {
					//search signatures by node name && namespace
					signatureToVerify =
						signaturesInDoc
							.Cast<XmlElement>()
							.Where((elt) => {
										string refValue = elt
											.GetXElement()
											.Descendants()
											.Elements("Reference")
											.Attributes("URI")
											.First()
											.Value;
										
							})
							.First();
				}
			}*/

			signedXml.LoadXml(signatureToVerify);
			return cert == null ? signedXml.CheckSignature() : signedXml.CheckSignature(cert, true);
			
		}

		private static bool _verifySignature(XmlDocument message, bool verifySignatureOnly = false, X509Certificate2 verifyOnThisCert = null, string nodeId=null, string nodeName=null, string nodeNamespace = null) {
			bool ret = false;
			X509Certificate2 cert = new X509Certificate2();
			if(verifySignatureOnly) {
				cert = verifyOnThisCert ?? CertificateProcessing.ReadCertificateFromXml(message.GetXDocument());
			}
			XmlDocument xmlDocument = message;
			//xmlDocument.PreserveWhitespace = true;

			XmlNodeList nodeList =
				xmlDocument.GetElementsByTagName(
					"Signature", SignedXml.XmlDsigNamespaceUrl
				);

			foreach(XmlElement sig in nodeList) {
				SignedXml signedXml = new SignedXml(xmlDocument);
				signedXml.LoadXml(sig);
				ret = verifySignatureOnly ? signedXml.CheckSignature(cert, true) : signedXml.CheckSignature();
			}

			return ret;
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
