using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using Space.CertificateSerialization.DataModel;
using Space.Core;
using Space.Core.Exceptions;
using Space.Core.Interfaces;

namespace Space.CertificateSerialization
{
	public class CertificateSerializer : ICertificateSerializer
	{
		public X509CertificateSerializable CertificateToSerializableCertificate(
			CertificateProcessor.CertificateSource source,
			string filePath,
			string nodeId)
		{
			switch (source)
			{
				case CertificateProcessor.CertificateSource.Xml:
					ICertificateProcessor cp = new CertificateProcessor();
					return new X509CertificateSerializable(cp.ReadCertificateFromXmlDocument(XDocument.Load(filePath), nodeId));
				case CertificateProcessor.CertificateSource.Base64:
					try
					{
						return new X509CertificateSerializable(new X509Certificate2(File.ReadAllBytes(filePath)));
					}
					catch (Exception e)
					{
						throw ExceptionFactory.GetException(ExceptionType.CertificateFileCorrupted, e.Message);
					}
				case CertificateProcessor.CertificateSource.Cer:
					try
					{
						X509Certificate2 cer = new X509Certificate2();
						if (Path.GetExtension(filePath) == ".p7b")
						{
							X509Certificate2Collection collection = new X509Certificate2Collection();
							collection.Import(filePath);
							if (collection.Count < 1)
							{
								throw ExceptionFactory.GetException(ExceptionType.NoCertificatesFound, filePath);
							}
							if (collection.Count == 1)
							{
								cer = collection[0];
							}
							if (collection.Count > 1)
							{
								return new X509CertificateSerializable(collection);
							}
						}
						else
						{
							cer.Import(filePath);
						}

						return new X509CertificateSerializable(cer);
					}
					catch (Exception e)
					{
						throw ExceptionFactory.GetException(ExceptionType.CertificateFileCorrupted, e.Message);
					}
				default:
					throw ExceptionFactory.GetException(ExceptionType.UnknownCertificateSource);
			}
		}
	}
}
