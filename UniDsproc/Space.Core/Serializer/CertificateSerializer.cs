using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;
using Space.Core.Communication;
using Space.Core.Exceptions;
using Space.Core.Interfaces;
using Space.Core.Processor;

namespace Space.Core.Serializer
{
	public class CertificateSerializer : ICertificateSerializer
	{
		public X509CertificateSerializable CertificateToSerializable(X509Certificate2 certificate) 
			=> new X509CertificateSerializable(certificate);

		public X509CertificateSerializable CertificateToSerializable(
			CertificateSource source,
			string filePath,
			string nodeId)
		{
			switch (source)
			{
				case CertificateSource.Xml:
					ICertificateProcessor cp = new CertificateUtils();
					return new X509CertificateSerializable(
						cp.ReadCertificateFromXmlDocument(XDocument.Load(filePath), nodeId));
				case CertificateSource.Base64:
					try
					{
						return new X509CertificateSerializable(new X509Certificate2(File.ReadAllBytes(filePath)));
					}
					catch (Exception e)
					{
						throw ExceptionFactory.GetException(ExceptionType.CertificateFileCorrupted, e.Message);
					}
				case CertificateSource.Cer:
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
