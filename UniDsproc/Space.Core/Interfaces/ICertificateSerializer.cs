using System.Security.Cryptography.X509Certificates;
using Space.Core.Communication;
using Space.Core.Processor;

namespace Space.Core.Interfaces
{
	public interface ICertificateSerializer
	{
		/// <summary>
		/// Reads signed file from disk and serializes certificate its specified node is signed with
		/// </summary>
		/// <param name="source">Source of te certificate (type of th file passed)</param>
		/// <param name="filePath">Path of th file to read</param>
		/// <param name="nodeId">Id of the signed node</param>
		/// <returns><see cref="X509CertificateSerializable"/></returns>
		X509CertificateSerializable CertificateToSerializable(
			CertificateSource source,
			string filePath,
			string nodeId);

		/// <summary>
		/// Creates serializable certificate from provided <see cref="X509Certificate2"/> instance.
		/// </summary>
		/// <param name="certificate">The certificate to create serializable from.</param>
		X509CertificateSerializable CertificateToSerializable(X509Certificate2 certificate);
	}
}
