using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using Microsoft.Owin.Hosting;
using Serilog;
using Topshelf;
using UniDsproc.Configuration;

namespace UniDsproc.Api
{
	internal class WebApiHost : ServiceControl, INotifyPropertyChanged
	{
		#region NotifyPropertyChanged

		public event PropertyChangedEventHandler PropertyChanged;

		protected virtual void OnPropertyChanged([CallerMemberName] string propertyName = null)
		{
			PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
		}

		#endregion

		#region Private

		private static readonly object _syncRoot = new object();
		private IDisposable _apiServer;
		private readonly HashSet<string> _allowedIpAddresses;

		#endregion

		#region Props

		public string Protocol { get; }
		public int Port { get; }

		private int _connectedClientsCount;
		public int ConnectedClientsCount
		{
			get => _connectedClientsCount;
			set
			{
				_connectedClientsCount = value;
				OnPropertyChanged();
			}
		}

		private bool _isActive;
		public bool IsActive
		{
			set
			{
				_isActive = value;
				OnPropertyChanged();
			}
			get => _isActive;
		}

		#endregion

		#region Ctor
		
		public WebApiHost(AppSettings settings)
		{
			Protocol = settings.ApiHost.Protocol;
			Port = settings.ApiHost.Port;
			_allowedIpAddresses = settings.ApiHost.AllowedIpAddresses;
			_allowedIpAddresses.Add("::1");
			_allowedIpAddresses.Add("localhost");
		} 

		#endregion

		#region Counters methods

		public void ClientConnected()
		{
			lock (_syncRoot)
			{
				ConnectedClientsCount++;
			}
		}

		public void ClientDisconnected()
		{
			lock (_syncRoot)
			{
				ConnectedClientsCount--;
			}
		}

		#endregion

		#region Methods to start / stop server

		public void Start()
		{
			IsActive = true;
			string baseAddress = $"{Protocol}://*:{Port}/";
			Log.Information("Starting listening on {address}", baseAddress);
			_apiServer = WebApp.Start<Startup>(baseAddress);
		}

		public void Stop()
		{
			if (_apiServer != null)
			{
				_apiServer.Dispose();
				_apiServer = null;
				IsActive = false;
			}
		}

		#endregion

		#region Security methods

		public bool IsIpAllowedToConnect(string ipAddress)
			=> !_allowedIpAddresses.Any() || _allowedIpAddresses.Contains(ipAddress);

		#endregion

		#region Topshelf service methods
		
		public bool Start(HostControl hostControl)
		{
			Start();
			return true;
		}

		public bool Stop(HostControl hostControl)
		{
			Stop();
			return true;
		} 

		#endregion
	}
}
