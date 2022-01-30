using System;
using System.Reflection;
using System.Resources;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;
using Space.Core.Communication;
using Space.Core.Interfaces;
using System.Linq.Expressions;

namespace Space.Core.Verifier
{
	public partial class SignatureVerifier
	{
		private static readonly Type _signedXmlType = typeof(SignedXml);
		private static readonly ResourceManager _securityResources =
			new ResourceManager("system.security", _signedXmlType.Assembly);

		//these methods from the SignedXml class still work with prefixed Signature elements, but they are private
		private static readonly ParameterExpression _thisSignedXmlParam = Expression.Parameter(_signedXmlType);
		private static readonly Func<SignedXml, bool> _checkSignatureFormat
			= Expression.Lambda<Func<SignedXml, bool>>(
				Expression.Call(
					_thisSignedXmlParam,
					_signedXmlType.GetMethod("CheckSignatureFormat", BindingFlags.NonPublic | BindingFlags.Instance)),
				_thisSignedXmlParam).Compile();

		private static readonly Func<SignedXml, bool> _checkDigestedReferences
			= Expression.Lambda<Func<SignedXml, bool>>(
				Expression.Call(
					_thisSignedXmlParam,
					_signedXmlType.GetMethod("CheckDigestedReferences", BindingFlags.NonPublic | BindingFlags.Instance)),
				_thisSignedXmlParam).Compile();

		public VerifierResponse CheckSignatureDs(XmlDocument xmlDoc, RSACryptoServiceProvider key)
		{
			if (key == null)
			{
				throw new ArgumentNullException(nameof(key));
			}

			SignedXml signedXml = new SignedXml(xmlDoc);

			//For XPath
			XmlNamespaceManager namespaceManager = new XmlNamespaceManager(xmlDoc.NameTable);
			namespaceManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
			//this prefix is arbitrary and used only for XPath

			XmlElement xmlSignature = xmlDoc.SelectSingleNode("//ds:Signature", namespaceManager) as XmlElement;

			signedXml.LoadXml(xmlSignature);

			//These are the three methods called in SignedXml's CheckSignature method, but the built-in CheckSignedInfo will not validate prefixed Signature elements

			var isSignatureValid = _checkSignatureFormat(signedXml) && _checkDigestedReferences(signedXml)
				&& CheckSignedInfo(signedXml, key);

			return isSignatureValid
				? VerifierResponse.Valid
				: VerifierResponse.Invalid("Signature is invalid");
		}

		private bool CheckSignedInfo(SignedXml signedXml, AsymmetricAlgorithm key)
		{
			//Copied from reflected System.Security.Cryptography.Xml.SignedXml
			SignatureDescription signatureDescription =
				CryptoConfig.CreateFromName(signedXml.SignatureMethod) as SignatureDescription;

			if (signatureDescription == null)
			{
				throw new CryptographicException(
					_securityResources.GetString("Cryptography_Xml_SignatureDescriptionNotCreated"));
			}

			Type type = Type.GetType(signatureDescription.KeyAlgorithm);
			Type type2 = key.GetType();
			if (type != type2
				&& !type.IsSubclassOf(type2)
				&& !type2.IsSubclassOf(type))
			{
				return false;
			}

			HashAlgorithm hashAlgorithm = signatureDescription.CreateDigest();
			if (hashAlgorithm == null)
			{
				throw new CryptographicException(
					_securityResources.GetString("Cryptography_Xml_CreateHashAlgorithmFailed"));
			}

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
	}
}
