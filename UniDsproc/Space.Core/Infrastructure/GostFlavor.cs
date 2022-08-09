using System.Diagnostics.CodeAnalysis;

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
