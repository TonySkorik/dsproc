using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace UniDsproc.Infrastructure
{
	[AttributeUsage(AttributeTargets.Property)]
	public class ArgBindingAttribute : Attribute
	{
		public string ArgumentName { get; }

		public ArgBindingAttribute(string argumentName)
		{
			this.ArgumentName = argumentName;
		}
	}

	static class CommandLineBind
	{
		public static Dictionary<string, PropertyInfo> BuildBindings(Type classToBind)
		{
			return
				classToBind
					.GetProperties()
					.Where(prop => Attribute.IsDefined(prop, typeof(ArgBindingAttribute)))
					.ToDictionary(
						(prop) => ((ArgBindingAttribute)prop.GetCustomAttributes(typeof(ArgBindingAttribute)).First())
							.ArgumentName,
						(prop) => prop
					);
		}
	}
}
