using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Serilog.Events;

namespace UniDsproc.Configuration
{
	public class AppSettings
	{
		public WebApiHostConfiguration ApiHost { set;get; }
		public LoggerConfiguration Logger { set; get; }
		public SignerConfiguration Singner { set; get; }

		public class WebApiHostConfiguration
		{
			public string Protocol { set; get; }
			public int Port { set; get; }
			public HashSet<string> AllowedIpAddresses { set; get; }
		}

		public class LoggerConfiguration
		{
			public string FilePath { set; get; }
			public LogEventLevel MinimumEventLevel { set; get; }
		}

		public class SignerConfiguration
		{
			public Dictionary<string, string> KnownThumbprints { set; get; } = new Dictionary<string, string>();
		}
	}
}
