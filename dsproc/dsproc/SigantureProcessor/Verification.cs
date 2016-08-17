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
using dsproc.DataModel;

namespace dsproc.SigantureProcessor {
	public static class Verification {

		#region [STANDARD]
		public static bool VerifySignature(string message, bool verifySignatureOnly = false) {
			XmlDocument xd = new XmlDocument();
			xd.Load(new StringReader(message));
			return VerifySignature(xd, verifySignatureOnly);
		}

		public static bool VerifySignature(XmlDocument message, bool verifySignatureOnly = false, X509Certificate2 verifyOnThisCert = null) {
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
