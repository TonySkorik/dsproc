using System;

namespace Space.Core.Exceptions
{
	public static class ExceptionExtensions
	{
		public static void Throw(this Exception ex)
		{
			throw ex;
		}
	}
}