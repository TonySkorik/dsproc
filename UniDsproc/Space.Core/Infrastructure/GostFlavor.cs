using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Space.Core.Infrastructure
{
	[SuppressMessage("ReSharper", "InconsistentNaming")]
	public enum GostFlavor
	{
		None,
		Gost_Obsolete,
		Gost2012_256,
		Gost2012_512
	}
}
