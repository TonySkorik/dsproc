using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Space.Core.Communication;
using Space.Core.Configuration;
using Space.Core.Exceptions;
using Space.Core.Interfaces;
using Space.Core.Processor;
using Space.Core.Verifier;

namespace Space.Core.Model
{
	public abstract class InputDataBase
	{
		public SignatureType SignatureType { get; set; }

		public string FilePath { get; set; }

		public string SignatureFilePath { get; set; }

		public string CertificateThumbprint { get; set; }

		public string CertificateFilePath { get; set; }

		public byte[] FileBytes { get; set; }

		public byte[] SignatureFileBytes { get; set; }

		public abstract VerifierResponse Verify(IVerifier verifier, SignatureVerificationParameters parameters);

		public X509Certificate2 GetCertificate()
		{
			X509Certificate2 ret;

			if (!string.IsNullOrEmpty(CertificateFilePath))
			{
				// load certificate from external file
				if (!File.Exists(CertificateFilePath))
				{
					throw new InvalidOperationException($"Certificate file {CertificateFilePath} does not exist.");
				}
				
				try
				{
					ret = new X509Certificate2();
					ret.Import(CertificateFilePath);
				}
				catch (Exception e)
				{
					throw ExceptionFactory.GetException(
						ExceptionType.CertificateImportException,
						CertificateFilePath,
						e.Message);
				}
			}
			else
			{
				ret = CertificateUtils.SearchCertificateByThumbprint(CertificateThumbprint);
			}
		}
	}
}
