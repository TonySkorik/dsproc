using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Xml.XPath;
using UniDsproc.Api.Helpers;
using UniDsproc.Api.Model;
using UniDsproc.Configuration;
using UniDsproc.DataModel.Security;

namespace UniDsproc.Api.Infrastructure
{
	internal class UserRestrictionsChecker
	{
		private const string XpathAndSeparator = "|AND|";
		private readonly Dictionary<string, UserRestrictions> _restrictions;

		public UserRestrictionsChecker(AppSettings appSettings)
		{
			_restrictions = appSettings.ApiHost.UserRestrictions
				?.ToDictionary(r => r.UserIp, r => r);
			
			_restrictions ??= new Dictionary<string, UserRestrictions>();
		}

		public bool IsUserAllowed(string userIp, SignerInputParameters inputParameters)
		{
			bool userHasRestrictions = 
				_restrictions.TryGetValue(userIp, out UserRestrictions userRestrictions);

			if (!userHasRestrictions)
			{
				return true;
			}

			if (userRestrictions.RestrictedSignatureTypes.Contains(inputParameters.ArgsInfo.SigType))
			{
				return false;
			}

			string xml = Encoding.UTF8.GetString(inputParameters.DataToSign);

			bool isRestrictedByXpath = IsRestrictedByXpath(xml, userRestrictions.RestrictedXmlXpathExpressions);

			return !isRestrictedByXpath;
		}

		private bool IsRestrictedByXpath(string xml, List<string> restrictingXpaths)
		{
			var xdoc = xml.TryParseAsXdocument();
			if (xdoc == null)
			{
				// means this data to sign is not a valid XML
				return false;
			}

			foreach (var combinedExpression in restrictingXpaths)
			{
				var expressions = combinedExpression.Split(
					new[] { XpathAndSeparator },
					StringSplitOptions.RemoveEmptyEntries);

				bool wasMatch = false;

				foreach (var expression in expressions)
				{
					
				}
			}

			return false;
		}
	}
}
