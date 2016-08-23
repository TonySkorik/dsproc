using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace SmartBind {
	[AttributeUsage(AttributeTargets.Property)]
	public class ArgBindingAttribute : Attribute {
		private string _argumentName;
		public string ArgumentName {
			get { return _argumentName; }
		}
		public ArgBindingAttribute(string ArgumentName) {
			_argumentName = ArgumentName;
		}
	}

	static class CommandLineBind {
		public static Dictionary<string, PropertyInfo> BuildBindings(Type classToBind) {
			return
				classToBind
				.GetProperties()
				.Where(prop => Attribute.IsDefined(prop, typeof (ArgBindingAttribute)))
				.ToDictionary(
					(prop) => ((ArgBindingAttribute)prop.GetCustomAttributes(typeof (ArgBindingAttribute)).First()).ArgumentName,
					(prop) => prop
				);
		}
	}
}
