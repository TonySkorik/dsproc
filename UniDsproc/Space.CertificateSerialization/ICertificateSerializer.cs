using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Space.CertificateSerialization.DataModel;
using Space.Core;

namespace Space.CertificateSerialization
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
		X509CertificateSerializable CertificateToSerializableCertificate(
			CertificateProcessor.CertificateSource source,
			string filePath,
			string nodeId);
	}
}
