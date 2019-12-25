using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using CryptoPro.Sharpei.Xml;
using Space.Core.Infrastructure;

namespace Space.Core
{
	/// <summary>
	/// SMEV 2 Sign
	/// </summary>
	/// <seealso cref="Space.Core.Interfaces.ISigner" />
	public partial class Signer
	{
		#region [UTILITY]

		public const string WsSecurityWsseNamespaceUrl =
			"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
		public const string WsSecurityWsuNamespaceUrl =
			"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

		internal class Smev2SignedXml : SignedXml
		{
			public Smev2SignedXml(XmlDocument document)
				: base(document)
			{ }

			public override XmlElement GetIdElement(XmlDocument document, string idValue)
			{
				XmlNamespaceManager nsmgr = new XmlNamespaceManager(document.NameTable);
				nsmgr.AddNamespace("wsu", WsSecurityWsuNamespaceUrl);
				return document.SelectSingleNode("//*[@wsu:Id='" + idValue + "']", nsmgr) as XmlElement;
			}
		}

		private const string WSU_NS =
			"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
		private const string SOAPENV_NS = "http://schemas.xmlsoap.org/soap/envelope/";
		private const string WSSE_NS =
			"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
		private const string DS_NS = "http://www.w3.org/2000/09/xmldsig#";

		#endregion

		#region [TEMPLATE GENERATION]
		private XmlDocument AddTemplate(XmlDocument baseDocument, X509Certificate2 certificate)
		{
			baseDocument.PreserveWhitespace = true;

			XmlNode root = baseDocument.SelectSingleNode("/*");
			string rootPrefix = root?.Prefix;

			XmlElement security = baseDocument.CreateElement("wsse", "Security", WSSE_NS);
			security.SetAttribute("actor", SOAPENV_NS, "http://smev.gosuslugi.ru/actors/smev");
			XmlElement securityToken = baseDocument.CreateElement("wsse", "BinarySecurityToken", WSSE_NS);
			securityToken.SetAttribute(
				"EncodingType",
				"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
			securityToken.SetAttribute(
				"ValueType",
				"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
			securityToken.SetAttribute("Id", WSU_NS, "CertId");
			securityToken.Prefix = "wsse";
			securityToken.InnerText = Convert.ToBase64String(certificate.RawData);
			XmlElement signature = baseDocument.CreateElement("Signature");
			XmlElement canonicMethod = baseDocument.CreateElement("CanonicalizationMethod");
			canonicMethod.SetAttribute("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#");
			XmlElement signatureMethod = baseDocument.CreateElement("SignatureMethod");
			signatureMethod.SetAttribute("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411");
			XmlElement keyInfo = baseDocument.CreateElement("KeyInfo");
			keyInfo.SetAttribute("Id", "key_info");
			XmlElement securityTokenReference = baseDocument.CreateElement("wsse", "SecurityTokenReference", WSSE_NS);
			XmlElement reference = baseDocument.CreateElement("wsse", "Reference", WSSE_NS);
			reference.SetAttribute("URI", "#CertId");
			reference.SetAttribute(
				"ValueType",
				"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");

			XmlElement startElement = baseDocument.GetElementsByTagName(rootPrefix + ":Header")[0] as XmlElement;
			startElement?.AppendChild(security).AppendChild(securityToken);
			startElement = baseDocument.GetElementsByTagName("wsse:Security")[0] as XmlElement;
			startElement?.AppendChild(signature);

			startElement = baseDocument.GetElementsByTagName("Signature")[0] as XmlElement;
			startElement?.AppendChild(keyInfo).AppendChild(securityTokenReference).AppendChild(reference);

			return baseDocument;
		}
		#endregion

		#region [SIGN SMEV 2]
		private XmlDocument SignSmev2(GostFlavor gostFlavor, XmlDocument doc, X509Certificate2 certificate)
		{
			XmlNode root = doc.SelectSingleNode("/*");
			string rootPrefix = root?.Prefix;
			//----------------------------------------------------------------------------------------------CREATE STRUCTURE
			XmlDocument tDoc = AddTemplate(doc, certificate);
			//----------------------------------------------------------------------------------------------ROOT PREFIX 
			XmlElement bodyElement = tDoc.GetElementsByTagName(rootPrefix + ":Body")[0] as XmlElement;
			string referenceUri = bodyElement?.GetAttribute("wsu:Id");
			//----------------------------------------------------------------------------------------------SignedXML CREATE
			//нужен для корректной отработки wsu:reference 
			Smev2SignedXml signedXml = new Smev2SignedXml(tDoc)
			{
				SigningKey = certificate.PrivateKey
			};
			//----------------------------------------------------------------------------------------------REFERNCE
			Reference reference = new Reference
			{
#pragma warning disable 612
				DigestMethod = GostAlgorithmSelector.GetHashAlgorithmDescriptor(gostFlavor),
				//CPSignedXml.XmlDsigGost3411UrlObsolete,
#pragma warning restore 612
				Uri = "#" + referenceUri
			};

			XmlDsigExcC14NTransform c14 = new XmlDsigExcC14NTransform();
			reference.AddTransform(c14);

			signedXml.AddReference(reference);
			//----------------------------------------------------------------------------------------------SIGNATURE SETUP
			signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
#pragma warning disable 612
			signedXml.SignedInfo.SignatureMethod = GostAlgorithmSelector.GetSignatureAlgorithmDescriptor(gostFlavor);
			//CPSignedXml.XmlDsigGost3410UrlObsolete;
#pragma warning disable 612
			//----------------------------------------------------------------------------------------------KEYINFO
			KeyInfo keyInfo = new KeyInfo();
			KeyInfoX509Data x509KeyInfo = new KeyInfoX509Data(certificate);
			keyInfo.AddClause(x509KeyInfo);
			signedXml.KeyInfo = keyInfo;
			//----------------------------------------------------------------------------------------------SIGN DOCUMENT
			signedXml.ComputeSignature();
			//----------------------------------------------------------------------------------------------GET XML
			XmlElement xmlDigitalSignature = signedXml.GetXml();
			//----------------------------------------------------------------------------------------------APPEND SIGNATURE TAGS
			tDoc.GetElementsByTagName("Signature")[0].PrependChild(
				tDoc.ImportNode(xmlDigitalSignature.GetElementsByTagName("SignatureValue")[0], true));
			tDoc.GetElementsByTagName("Signature")[0].PrependChild(
				tDoc.ImportNode(xmlDigitalSignature.GetElementsByTagName("SignedInfo")[0], true));
			((XmlElement)tDoc.GetElementsByTagName("Signature")[0]).SetAttribute("xmlns", DS_NS);

			return tDoc;
		}
		#endregion
	}
}