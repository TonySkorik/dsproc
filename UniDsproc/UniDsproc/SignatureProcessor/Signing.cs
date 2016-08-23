using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using CryptoPro.Sharpei.Xml;

namespace UniDsproc.SignatureProcessor {

	public enum SignatureType {Smev2BaseDetached, Smev2ChargeEnveloped, Smev2SidebysideDetached, Smev3BaseDetached, SigDetached , Unknown};

	public static class Signing {
		//public static string Sign(SigningMode mode, X509Certificate2 cert, XmlDocument signThis, bool assignDs, string nodeToSign, string nodeNamespace) {
		public static string Sign(SignatureType mode, X509Certificate2 cert, XmlDocument signThis, bool assignDs, string nodeToSign) {

			XmlDocument signedXmlDoc = new XmlDocument();

			AsymmetricAlgorithm privateKey;
			
			try {
				privateKey = cert.PrivateKey;
			} catch(Exception e) {
				throw new Exception($"PRIVATE_KEY_MISSING] Certificate (subject: <{cert.Subject}>) private key not found. Original message: <{e.Message}>");
			}
			try {
				switch (mode) {
					//case SigningMode.Simple:
					case SignatureType.Smev2SidebysideDetached:
						if(string.IsNullOrEmpty(nodeToSign)) {
							throw new Exception($"NODE_ID_REQUIRED] <node_id> value is empty. It is required to have a value");
						}
						signedXmlDoc = SignXmlNode(signThis, privateKey, cert, nodeToSign);
						break;
					//case SigningMode.SimpleEnveloped:
					case SignatureType.Smev2ChargeEnveloped:
						signedXmlDoc = SignXmlFileEnveloped(signThis, privateKey, cert);
						break;
					//case SigningMode.Smev2:
					case SignatureType.Smev2BaseDetached:
						signedXmlDoc = SignXmlFileSmev2(signThis, privateKey, cert);
						break;
					//case SigningMode.Smev3:
					case SignatureType.Smev3BaseDetached:
						if (string.IsNullOrEmpty(nodeToSign)) {
							throw new Exception($"NODE_ID_REQUIRED] <node_id> value is empty. It is required to have a value");
						}
						signedXmlDoc = SignXmlFileSmev3(signThis, privateKey, cert, nodeToSign, assignDs);
						break;
					//case SigningMode.Detached:
					case SignatureType.SigDetached:
						return Convert.ToBase64String(SignXmlFileDetached(signThis, privateKey, cert, nodeToSign, assignDs));
				}
			} catch (Exception e) {
				throw new Exception($"UNKNOWN_CRYPTO_EX] Original message: {e.Message}");
			}

			return signedXmlDoc.InnerXml;
		}
		public static string Sign(SignatureType mode, string certificateThumbprint, string signThisPath, bool assignDs, string nodeToSign, bool ignoreExpiredCert=false) {
			XmlDocument signThis = new XmlDocument();
			signThis.Load(signThisPath);
			return Sign(mode, certificateThumbprint, signThis, assignDs, nodeToSign, ignoreExpiredCert);
		}

		public static string Sign(SignatureType mode, string certificateThumbprint, XmlDocument signThis, bool assignDs, string nodeToSign, bool ignoreExpiredCert=false) {
			X509Certificate2 certificate = CertificateProcessing.SearchCertificateByThumbprint(certificateThumbprint);

			if (!ignoreExpiredCert && CertificateProcessing.IsCertificateExpired(certificate)) {
				throw new Exception($"CERT_EXPIRED] Certificate with thumbprint <{certificate.Thumbprint}> expired!");
			}

			return Sign(mode, certificate, signThis, assignDs, nodeToSign);
		}

		#region [SIMPLE NODE SIGN]

		private static XmlNode getNodeWithAttributeValue(XmlNodeList nodelist, string attributeValue) {
			XmlNode ret = null;
			foreach(XmlNode xn in nodelist) {
				if (xn.HasChildNodes) {
					ret = getNodeWithAttributeValue(xn.ChildNodes, attributeValue);
					if ( ret!= null) break;
				}
				if (xn.Attributes!=null && xn.Attributes.Count != 0) {
					foreach (XmlAttribute xa in xn.Attributes) {
						if (xa.Value == attributeValue) {
							ret = xn;
							break;
						}
					}
				}
			}
			return ret;
		}

		public static XmlDocument SignXmlNode(XmlDocument doc, AsymmetricAlgorithm key, X509Certificate2 certificate, string nodeId) {

			//----------------------------------------------------------------------------------------------CREATE SIGNED XML
			SignedXml signedXml = new SignedXml(doc) { SigningKey = key };
			//----------------------------------------------------------------------------------------------REFERNCE
			Reference reference = new Reference {
				Uri = "#"+nodeId,
				#pragma warning disable 612
				DigestMethod = CryptoPro.Sharpei.Xml.CPSignedXml.XmlDsigGost3411UrlObsolete
				#pragma warning disable 612
			};

			XmlDsigExcC14NTransform c14 = new XmlDsigExcC14NTransform();
			reference.AddTransform(c14);

			// Add the reference to the SignedXml object.
			signedXml.AddReference(reference);
			//----------------------------------------------------------------------------------------------SIGNATURE SETUP
			signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
			signedXml.SignedInfo.SignatureMethod = CryptoPro.Sharpei.Xml.CPSignedXml.XmlDsigGost3410UrlObsolete;
			//----------------------------------------------------------------------------------------------KEYINFO
			KeyInfo keyInfo = new KeyInfo();
			KeyInfoX509Data X509KeyInfo = new KeyInfoX509Data(certificate);
			keyInfo.AddClause(X509KeyInfo);
			signedXml.KeyInfo = keyInfo;
			//----------------------------------------------------------------------------------------------SIGN DOCUMENT
			signedXml.ComputeSignature();
			//----------------------------------------------------------------------------------------------GET XML
			XmlElement xmlDigitalSignature = signedXml.GetXml();
			//=============================================================================APPEND SIGNATURE TO DOCUMENT
			
			getNodeWithAttributeValue(doc.ChildNodes, nodeId)?.ParentNode?.AppendChild(xmlDigitalSignature);

			return doc;
		}
		#endregion

		#region [SIMPLE ENVELOPED SIGN]

		public static XmlDocument SignXmlFileEnveloped(XmlDocument doc, AsymmetricAlgorithm key, X509Certificate2 certificate, string nodeId=null) {
			nodeId = string.Empty;
			//----------------------------------------------------------------------------------------------CREATE SIGNED XML
			SignedXml signedXml = new SignedXml(doc) { SigningKey = key };
			//----------------------------------------------------------------------------------------------REFERNCE
			Reference reference = new Reference {
				Uri = nodeId,
				#pragma warning disable 612
				DigestMethod = CryptoPro.Sharpei.Xml.CPSignedXml.XmlDsigGost3411UrlObsolete
				#pragma warning disable 612
			};

			XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
			reference.AddTransform(env);
			XmlDsigExcC14NTransform c14 = new XmlDsigExcC14NTransform();
			reference.AddTransform(c14);

			// Add the reference to the SignedXml object.
			signedXml.AddReference(reference);
			//----------------------------------------------------------------------------------------------SIGNATURE SETUP
			signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
			signedXml.SignedInfo.SignatureMethod = CryptoPro.Sharpei.Xml.CPSignedXml.XmlDsigGost3410UrlObsolete;
			//----------------------------------------------------------------------------------------------KEYINFO
			KeyInfo keyInfo = new KeyInfo();
			KeyInfoX509Data X509KeyInfo = new KeyInfoX509Data(certificate);
			keyInfo.AddClause(X509KeyInfo);
			signedXml.KeyInfo = keyInfo;
			//----------------------------------------------------------------------------------------------SIGN DOCUMENT
			signedXml.ComputeSignature();
			//----------------------------------------------------------------------------------------------GET XML
			XmlElement xmlDigitalSignature = signedXml.GetXml();
			//----------------------------------------------------------------------------------------------APPEND SIGNATURE
			XmlNode root = doc.SelectSingleNode("/*");
			root?.AppendChild(doc.ImportNode(xmlDigitalSignature, true));

			//if (doc.FirstChild is XmlDeclaration)
			//{
			// doc.RemoveChild(doc.FirstChild);
			//}
			//----------------------------------------------------------------------------------------------WRITE DOCUMENT
			return doc;
		}

		#endregion

		#region [SMEV 2 (side by side)]

		#region [UTILITY]

		public const string WSSecurityWSSENamespaceUrl =
			"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
		public const string WSSecurityWSUNamespaceUrl =
			"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

		class Smev2SignedXml : SignedXml {
			public Smev2SignedXml(XmlDocument document)
				: base(document) { }

			public override XmlElement GetIdElement(XmlDocument document, string idValue) {
				XmlNamespaceManager nsmgr = new XmlNamespaceManager(document.NameTable);
				nsmgr.AddNamespace("wsu", WSSecurityWSUNamespaceUrl);
				return document.SelectSingleNode("//*[@wsu:Id='" + idValue + "']", nsmgr) as XmlElement;
			}
		}
		//----------------------------------------------------------------------------------------------------------------------------------------------------ADD TEMPLATE
		public static string wsu_ = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
		public static string soapenv_ = "http://schemas.xmlsoap.org/soap/envelope/";
		public static string wsse_ = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
		public static string ds_ = "http://www.w3.org/2000/09/xmldsig#";

		#endregion

		#region [TEMPLATE GENERATION]

		static XmlDocument AddTemplate(XmlDocument base_document, X509Certificate2 certificate) {

			base_document.PreserveWhitespace = true;

			XmlNode root = base_document.SelectSingleNode("/*");
			string rootPrefix = root.Prefix;

			XmlElement security = base_document.CreateElement("wsse", "Security", wsse_);
			security.SetAttribute("actor", soapenv_, "http://smev.gosuslugi.ru/actors/smev");
			XmlElement securityToken = base_document.CreateElement("wsse", "BinarySecurityToken", wsse_);
			securityToken.SetAttribute("EncodingType",
						"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
			securityToken.SetAttribute("ValueType",
						"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
			securityToken.SetAttribute("Id", wsu_, "CertId");
			securityToken.Prefix = "wsse";
			securityToken.InnerText = Convert.ToBase64String(certificate.RawData);
			XmlElement signature = base_document.CreateElement("Signature");
			XmlElement canonicMethod = base_document.CreateElement("CanonicalizationMethod");
			canonicMethod.SetAttribute("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#");
			XmlElement signatureMethod = base_document.CreateElement("SignatureMethod");
			signatureMethod.SetAttribute("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411");
			XmlElement keyInfo = base_document.CreateElement("KeyInfo");
			keyInfo.SetAttribute("Id", "key_info");
			XmlElement securityTokenReference = base_document.CreateElement("wsse", "SecurityTokenReference", wsse_);
			XmlElement reference = base_document.CreateElement("wsse", "Reference", wsse_);
			reference.SetAttribute("URI", "#CertId");
			reference.SetAttribute("ValueType",
						"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");

			XmlElement startElement = base_document.GetElementsByTagName(rootPrefix + ":Header")[0] as XmlElement;
			startElement?.AppendChild(security).AppendChild(securityToken);
			startElement = base_document.GetElementsByTagName("wsse:Security")[0] as XmlElement;
			startElement?.AppendChild(signature);

			startElement = base_document.GetElementsByTagName("Signature")[0] as XmlElement;
			startElement?.AppendChild(keyInfo).AppendChild(securityTokenReference).AppendChild(reference);

			return base_document;
		}

		#endregion

		#region [SIGN SMEV 2] Signing function
		public static XmlDocument SignXmlFileSmev2(XmlDocument doc, AsymmetricAlgorithm key, X509Certificate2 certificate) {

			XmlNode root = doc.SelectSingleNode("/*");
			string rootPrefix = root.Prefix;
			//----------------------------------------------------------------------------------------------CREATE STRUCTURE
			XmlDocument tDoc = AddTemplate(doc, certificate);
			//----------------------------------------------------------------------------------------------ROOT PREFIX 
			XmlElement bodyElement = tDoc.GetElementsByTagName(rootPrefix + ":Body")[0] as XmlElement;
			string referenceUri = bodyElement.GetAttribute("wsu:Id");
			//----------------------------------------------------------------------------------------------SignedXML CREATE
			//нужен для корректной отработки wsu:reference 
			Smev2SignedXml signedXml = new Smev2SignedXml(tDoc) {
				SigningKey = certificate.PrivateKey
			};
			//----------------------------------------------------------------------------------------------REFERNCE
			Reference reference = new Reference {
				DigestMethod = CryptoPro.Sharpei.Xml.CPSignedXml.XmlDsigGost3411UrlObsolete,
				Uri = "#"+referenceUri
			};

			XmlDsigExcC14NTransform c14 = new XmlDsigExcC14NTransform();
			reference.AddTransform(c14);

#pragma warning disable 612
			//reference.DigestMethod = CryptoPro.Sharpei.Xml.CPSignedXml.XmlDsigGost3411UrlObsolete;
#pragma warning disable 612

			signedXml.AddReference(reference);
			//----------------------------------------------------------------------------------------------SIGNATURE SETUP
			signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
#pragma warning disable 612
			signedXml.SignedInfo.SignatureMethod = CryptoPro.Sharpei.Xml.CPSignedXml.XmlDsigGost3410UrlObsolete;
#pragma warning disable 612
			//----------------------------------------------------------------------------------------------KEYINFO
			KeyInfo keyInfo = new KeyInfo();
			KeyInfoX509Data X509KeyInfo = new KeyInfoX509Data(certificate);
			keyInfo.AddClause(X509KeyInfo);
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

			return tDoc;
		}

		#endregion

		#endregion

		#region [SMEV 3]

		#region [UTILITY]
		private static void _assignNsPrefix(XmlElement element, string prefix) {
			element.Prefix = prefix;
			foreach(var child in element.ChildNodes) {
				if(child is XmlElement) {
					_assignNsPrefix(child as XmlElement, prefix);
				}
			}
		}
		#endregion

		public static XmlDocument SignXmlFileSmev3(XmlDocument doc, AsymmetricAlgorithm key, X509Certificate2 certificate, string signingNodeId, bool assignDs) {
			XmlNamespaceManager nsm = new XmlNamespaceManager(doc.NameTable);
			nsm.AddNamespace("ns", "urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1");
			nsm.AddNamespace("ns1", "urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1");
			nsm.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");


			SignedXml sxml = new SignedXml(doc) { SigningKey = key };

			//=====================================================================================REFERENCE TRASFORMS
			Reference reference = new Reference {
				Uri = "#" + signingNodeId,
				#pragma warning disable 612
				//Расчет хеш-суммы ГОСТ Р 34.11-94 http://www.w3.org/2001/04/xmldsig-more#gostr3411
				DigestMethod = CryptoPro.Sharpei.Xml.CPSignedXml.XmlDsigGost3411UrlObsolete
				#pragma warning disable 612
			};

			XmlDsigExcC14NTransform excC14n = new XmlDsigExcC14NTransform();
			reference.AddTransform(excC14n);

			XmlDsigSmevTransform smevTransform = new XmlDsigSmevTransform();
			reference.AddTransform(smevTransform);
			
			sxml.AddReference(reference);

			//=========================================================================================CREATE SIGNATURE
			sxml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

			//Формирование подписи ГОСТ Р 34.10-2001 http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411 
			sxml.SignedInfo.SignatureMethod = CryptoPro.Sharpei.Xml.CPSignedXml.XmlDsigGost3410UrlObsolete;
			KeyInfo keyInfo = new KeyInfo();
			KeyInfoX509Data X509KeyInfo = new KeyInfoX509Data(certificate);
			keyInfo.AddClause(X509KeyInfo);
			sxml.KeyInfo = keyInfo;

			sxml.ComputeSignature();

			XmlElement signature = sxml.GetXml();
			//==================================================================================================add ds:
			if(assignDs) {
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
				if(description == null) {
					throw new CryptographicException(
						$"Не удалось создать объект SignatureDescription по имени [{sxml.SignedInfo.SignatureMethod}]");
				}
				HashAlgorithm hash = description.CreateDigest();
				if(hash == null) {
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
			doc.GetElementsByTagName("CallerInformationSystemSignature",
						"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1")[0].InnerXml = "";
			doc.GetElementsByTagName("CallerInformationSystemSignature",
						"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1")[0].AppendChild(signature);

			//bool s = VerifySignature(doc);
			//MessageBox.Show($"Signature : {s}", "Signature validation");

			return doc;
		}



		public static XmlDocument SignXmlFileSmev3Enveloped(XmlDocument doc, AsymmetricAlgorithm key, X509Certificate2 certificate, string signingNodeId, bool assignDs) {

			XmlNamespaceManager nsm = new XmlNamespaceManager(doc.NameTable);
			nsm.AddNamespace("ns", "urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1");
			nsm.AddNamespace("ns1", "urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1");
			nsm.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");


			SignedXml sxml = new SignedXml(doc) { SigningKey = key };

			//=====================================================================================REFERENCE TRASFORMS
			Reference reference = new Reference {
				Uri = "#" + signingNodeId,
#pragma warning disable 612
				//Расчет хеш-суммы ГОСТ Р 34.11-94 http://www.w3.org/2001/04/xmldsig-more#gostr3411
				DigestMethod = CryptoPro.Sharpei.Xml.CPSignedXml.XmlDsigGost3411UrlObsolete
#pragma warning disable 612
			};

			XmlDsigExcC14NTransform excC14n = new XmlDsigExcC14NTransform();
			reference.AddTransform(excC14n);

			XmlDsigSmevTransform smevTransform = new XmlDsigSmevTransform();
			reference.AddTransform(smevTransform);

			XmlDsigEnvelopedSignatureTransform envelopedSigTransform = new XmlDsigEnvelopedSignatureTransform();
			reference.AddTransform(envelopedSigTransform);
			/*
			if (isAck) {
				
			} 
			*/
			sxml.AddReference(reference);

			//=========================================================================================CREATE SIGNATURE
			sxml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

			//Формирование подписи ГОСТ Р 34.10-2001 http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411 
			sxml.SignedInfo.SignatureMethod = CryptoPro.Sharpei.Xml.CPSignedXml.XmlDsigGost3410UrlObsolete;
			KeyInfo keyInfo = new KeyInfo();
			KeyInfoX509Data X509KeyInfo = new KeyInfoX509Data(certificate);
			keyInfo.AddClause(X509KeyInfo);
			sxml.KeyInfo = keyInfo;

			sxml.ComputeSignature();

			XmlElement signature = sxml.GetXml();
			//==================================================================================================add ds:
			if(assignDs) {
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
				if(description == null) {
					throw new CryptographicException(
						$"Не удалось создать объект SignatureDescription по имени [{sxml.SignedInfo.SignatureMethod}]");
				}
				HashAlgorithm hash = description.CreateDigest();
				if(hash == null) {
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
			doc.GetElementsByTagName("CallerInformationSystemSignature",
						"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1")[0].InnerXml = "";
			doc.GetElementsByTagName("CallerInformationSystemSignature",
						"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1")[0].AppendChild(signature);

			//bool s = VerifySignature(doc);
			//MessageBox.Show($"Signature : {s}", "Signature validation");

			return doc;
		}

		#endregion

		#region [DETACHED]

		public static byte[] SignXmlFileDetached(XmlDocument doc, AsymmetricAlgorithm key, X509Certificate2 certificate,
													string signingNodeId, bool assignDs) {

			ContentInfo contentInfo = new ContentInfo(Encoding.UTF8.GetBytes(doc.OuterXml));
			SignedCms signedCms = new SignedCms(contentInfo, true);
			CmsSigner cmsSigner = new CmsSigner(certificate) { IncludeOption = X509IncludeOption.EndCertOnly };
			signedCms.ComputeSignature(cmsSigner);
			//  Кодируем CMS/PKCS #7 подпись сообщения.
			return signedCms.Encode();
		}

		#endregion
	}
}
