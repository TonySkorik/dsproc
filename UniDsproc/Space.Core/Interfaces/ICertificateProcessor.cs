using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;
using Space.Core.Configuration;

namespace Space.Core.Interfaces
{
	public interface ICertificateProcessor
	{
		/// <summary>
		/// Search LocalMachine and then CurrentUser stores for the certificate with matching thumbprint
		/// </summary>
		/// <param name="certificateThumbprint">A thumbprint of the certificate to search for</param>
		/// <returns><see cref="X509Certificate2"/></returns>
		X509Certificate2 SearchCertificateByThumbprint(string certificateThumbprint);

		/// <summary>
		/// Search desired location for the certificate with matching thumbprint
		/// </summary>
		/// <param name="certificateThumbprint">A thumbprint of the certificate to search for</param>
		/// <param name="storeLocation">Desired <see cref="StoreLocation"/></param>
		/// <returns><see cref="X509Certificate2"/></returns>
		X509Certificate2 GetCertificateByThumbprint(string certificateThumbprint, StoreLocation storeLocation);

		/// <summary>
		/// Get all certificates from desired store
		/// </summary>
		/// <param name="storeLocation">Desired <see cref="StoreLocation"/></param>
		/// <returns><see cref="IEnumerable{T}"/> of <see cref="X509Certificate2"/></returns>
		IEnumerable<X509Certificate2> GetAllCertificatesFromStore(StoreLocation storeLocation);

		/// <summary>
		/// Shows standard Windows UI for certificate selection from desired store
		/// </summary>
		/// <param name="storeLocation">Desired <see cref="StoreLocation"/></param>
		/// <returns><see cref="X509Certificate2"/></returns>
		X509Certificate2 SelectCertificateUi(StoreLocation storeLocation);

		/// <summary>
		/// Reads certificate from specified certificate bytes.
		/// </summary>
		/// <param name="certificateFileBytes">The certificate bytes.</param>
		X509Certificate2 ReadCertificateFromCertificateFile(byte[] certificateFileBytes);

		/// <summary>
		/// Loads signed XML document from disk and reads a certificate which a specified node is signed with
		/// </summary>
		/// <param name="signedXmlPath">Path of the XML document to read</param>
		/// <param name="nodeId">Identifier of the signed node</param>
		/// <returns><see cref="X509Certificate2"/></returns>
		X509Certificate2 ReadCertificateFromXml(string signedXmlPath, string nodeId);

		/// <summary>
		/// Loads signed XML document from disk and reads a certificate which a specified node is signed with
		/// </summary>
		/// <param name="signedFileBytes">Signed file bytes.</param>
		/// <param name="signatureType">The signature type to determine how to read the provided file.</param>
		/// <param name="nodeId">The signed node id for XML signature cases.</param>
		/// <returns><see cref="X509Certificate2"/></returns>
		X509Certificate2 ReadCertificateFromSignedFile(
			SignatureType signatureType,
			byte[] signedFileBytes,
			byte[] signatureFileBytes = null,
			string nodeId = null);

		/// <summary>
		/// Reads a certificate which a specified node is signed with
		/// </summary>
		/// <param name="signedXml">Signed <see cref="XDocument"/></param>
		/// <param name="nodeId">Identifier of the signed node</param>
		/// <returns><see cref="X509Certificate2"/></returns>
		X509Certificate2 ReadCertificateFromXmlDocument(XDocument signedXml, string nodeId);

		/// <summary>
		/// Determines wheter certificate is expired
		/// </summary>
		/// <param name="certificate"><see cref="X509Certificate2"/> to analyze</param>
		/// <returns><see cref="bool"/></returns>
		bool IsCertificateExpired(X509Certificate2 certificate);

		/// <summary>
		/// Determines wheter passed document is built in Smev2 manner (has Header and wsse:Security elements)
		/// </summary>
		/// <param name="document"><see cref="XDocument"/> to analyze</param>
		/// <returns></returns>
		bool MessageIsSmev2Base(XDocument document);
	}
}
