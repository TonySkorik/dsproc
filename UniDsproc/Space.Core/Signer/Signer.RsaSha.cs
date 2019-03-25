using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Space.Core.Configuration;
using Space.Core.Exceptions;

namespace Space.Core
{
	/// <summary>
	/// RSA + SHA Sign
	/// </summary>
	/// <seealso cref="Space.Core.Interfaces.ISigner" />
	public partial class Signer
	{
		#region [Parametrized RSA(x) + SHA(y)]
		private byte[] SignStringRsaSha(string stringToSign, X509Certificate2 certificate, ShaAlgorithmType shaType)
		{
			byte[] msg = Encoding.UTF8.GetBytes(stringToSign);
			//RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
			RSACryptoServiceProvider rsa = certificate.PrivateKey as RSACryptoServiceProvider;
			if (rsa != null)
			{
				//rsa.FromXmlString(certificate.PrivateKey.ToXmlString(true));
				return rsa.SignData(msg, CryptoConfig.MapNameToOID(shaType.ToString().ToUpper()));
			}

			throw ExceptionFactory.GetException(ExceptionType.CERTIFICATE_KEY_CONVERSION_FAILED);
		}
		#endregion

		#region [RSA 2048 + SHA256]
		private byte[] SignStringRsa2048Sha256(string stringToSign, X509Certificate2 certificate)
		{
			if (certificate.PrivateKey.KeySize != 2048)
			{
				throw new Exception(
					$"CERTIFICATE_PRIVATE_KEY_INVALID_LENGTH] RSA 2048 algorithm expects certificate private key size to be of 2048. Size of {certificate.PrivateKey.KeySize} found. Use certificate with 2048 key size.");
			}

			byte[] msg = Encoding.UTF8.GetBytes(stringToSign);
			RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
			rsa.FromXmlString(certificate.PrivateKey.ToXmlString(true));
			// stackoverflow says that following might not work every time and suggests using MapNameToOID("SHA256")
			// http://stackoverflow.com/a/7475985
			//return rsa.SignData(msg, new SHA256CryptoServiceProvider());
			return rsa.SignData(msg, CryptoConfig.MapNameToOID("SHA256"));
		}
		#endregion
	}
}