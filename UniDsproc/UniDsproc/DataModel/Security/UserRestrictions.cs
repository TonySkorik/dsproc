using System.Collections.Generic;
using Space.Core.Configuration;

namespace UniDsproc.DataModel.Security
{
	public class UserRestrictions
	{
		public string UserIp { set; get; }
		public HashSet<SignatureType> RestrictedSignatureTypes { set; get; }

		/// <summary>
		/// Contains XPath expressions which evaluate to <c>true</c> if XML is restricted for specified user. 
		/// </summary>
		/// <remarks>Each line is combined with other lines with OR operator;
		/// Each line may consist of several pars separated by separator <c>|AND|</c>. These parts are combined with AND operator.</remarks>
		public List<string> RestrictedXmlXpathExpressions { set; get; } 
	}
}
