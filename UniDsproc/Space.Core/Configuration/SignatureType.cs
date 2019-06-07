using System.Diagnostics.CodeAnalysis;

namespace Space.Core.Configuration
{
	[SuppressMessage("ReSharper", "InconsistentNaming")]
	public enum SignatureType
	{
		Unknown,

		Smev2BaseDetached,
		Smev2ChargeEnveloped,
		Smev2SidebysideDetached,

		Smev3BaseDetached,
		Smev3SidebysideDetached,
		Smev3Ack,
		
		SigDetached,
		SigDetachedAllCert,
		SigDetachedNoCert,

		Pkcs7String,
		Pkcs7StringNoCert,
		Pkcs7StringAllCert,

		Rsa2048Sha256String,
		RsaSha256String
	};	
}