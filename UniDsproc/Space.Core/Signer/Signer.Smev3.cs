using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using CryptoPro.Sharpei.Xml;

namespace Space.Core
{
	/// <summary>
	/// SMEV 3 Sign
	/// </summary>
	/// <seealso cref="Space.Core.Interfaces.ISigner" />
	public partial class Signer
	{
		#region [UTILITY]
		private void _assignNsPrefix(XmlElement element, string prefix)
		{
			element.Prefix = prefix;
			foreach (var child in element.ChildNodes)
			{
				if (child is XmlElement)
				{
					_assignNsPrefix(child as XmlElement, prefix);
				}
			}
		}
		#endregion

		#region [SIGN SMEV 3]
		private XmlDocument SignXmlFileSmev3(
			XmlDocument doc,
			X509Certificate2 certificate,
			string signingNodeId,
			bool assignDs,
			bool isAck = false,
			bool isSidebyside = false)
		{
			XmlNamespaceManager nsm = new XmlNamespaceManager(doc.NameTable);
			nsm.AddNamespace("ns", "urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1");
			nsm.AddNamespace("ns1", "urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1");
			nsm.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");

			SignedXml sxml = new SignedXml(doc)
			{
				SigningKey = certificate.PrivateKey
			};

			//=====================================================================================REFERENCE TRASFORMS
			Reference reference = new Reference
			{
				Uri = "#" + signingNodeId,
#pragma warning disable 612
				//Расчет хеш-суммы ГОСТ Р 34.11-94 http://www.w3.org/2001/04/xmldsig-more#gostr3411
				DigestMethod = CPSignedXml.XmlDsigGost3411UrlObsolete
#pragma warning disable 612
			};

			XmlDsigExcC14NTransform excC14N = new XmlDsigExcC14NTransform();
			reference.AddTransform(excC14N);

			XmlDsigSmevTransform smevTransform = new XmlDsigSmevTransform();
			reference.AddTransform(smevTransform);

			if (isAck)
			{
				XmlDsigEnvelopedSignatureTransform enveloped = new XmlDsigEnvelopedSignatureTransform();
				reference.AddTransform(enveloped);
			}

			sxml.AddReference(reference);

			//=========================================================================================CREATE SIGNATURE
			sxml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

			//Формирование подписи ГОСТ Р 34.10-2001 http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411 
			sxml.SignedInfo.SignatureMethod = CPSignedXml.XmlDsigGost3410UrlObsolete;
			KeyInfo keyInfo = new KeyInfo();
			KeyInfoX509Data X509KeyInfo = new KeyInfoX509Data(certificate);
			keyInfo.AddClause(X509KeyInfo);
			sxml.KeyInfo = keyInfo;

			sxml.ComputeSignature();

			XmlElement signature = sxml.GetXml();
			//==================================================================================================add ds:
			if (assignDs)
			{
				_assignNsPrefix(signature, "ds");
				XmlElement xmlSignedInfo = signature.SelectSingleNode("ds:SignedInfo", nsm) as XmlElement;

				XmlDocument document = new XmlDocument();
				document.PreserveWhitespace = false;
				document.LoadXml(xmlSignedInfo.OuterXml);

				//create new canonicalization object based on original one
				Transform canonicalizationMethodObject = sxml.SignedInfo.CanonicalizationMethodObject;
				canonicalizationMethodObject.LoadInput(document);

				//get new hshing object based on original one
				SignatureDescription description =
					CryptoConfig.CreateFromName(sxml.SignedInfo.SignatureMethod) as SignatureDescription;
				if (description == null)
				{
					throw new CryptographicException(
						$"Не удалось создать объект SignatureDescription по имени [{sxml.SignedInfo.SignatureMethod}]");
				}

				HashAlgorithm hash = description.CreateDigest();
				if (hash == null)
				{
					throw new CryptographicException(
						$"Не удалось создать объект HashAlgorithm из SignatureDescription по имени [{sxml.SignedInfo.SignatureMethod}]");
				}

				//compute new SignedInfo digest value
				byte[] hashVal = canonicalizationMethodObject.GetDigestedOutput(hash);

				//compute new signature
				XmlElement xmlSignatureValue = signature.SelectSingleNode("ds:SignatureValue", nsm) as XmlElement;
				xmlSignatureValue.InnerText =
					Convert.ToBase64String(description.CreateFormatter(sxml.SigningKey).CreateSignature(hashVal));
			}

			//=============================================================================APPEND SIGNATURE TO DOCUMENT
			if (!isSidebyside)
			{
				doc.GetElementsByTagName(
					"CallerInformationSystemSignature",
					"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1")[0].InnerXml = "";
				doc.GetElementsByTagName(
					"CallerInformationSystemSignature",
					"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1")[0].AppendChild(signature);
			}
			else
			{
				GetNodeWithAttributeValue(doc.ChildNodes, signingNodeId)?.ParentNode?.AppendChild(signature);
			}

			return doc;
		}
		#endregion
	}
}