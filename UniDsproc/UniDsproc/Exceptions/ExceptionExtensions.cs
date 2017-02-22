using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UniDsproc.Exceptions {
	public static class ExceptionExtensions {
		public static void Throw(this Exception ex) {
			throw ex;
		}
	}
}
