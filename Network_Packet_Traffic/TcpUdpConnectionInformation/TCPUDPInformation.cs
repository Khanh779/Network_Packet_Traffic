using System;
using System.Net.NetworkInformation;

namespace Network_Packet_Traffic.TcpUdpConnectionInformation
{
    public class TCPUDPInformation
    {
        IPGlobalProperties netproperties;


        public TCPUDPInformation()
        {
            netproperties = IPGlobalProperties.GetIPGlobalProperties();

        }

        public void Start()
        {
            var Tcpconnections = netproperties.GetActiveTcpConnections();
            var Udpconnections = netproperties.GetActiveUdpListeners();

            Console.WriteLine("Active TCP Connections");

            foreach (var connection in Tcpconnections)
            {

                Console.WriteLine($"Local: {connection.LocalEndPoint}, Remote: {connection.RemoteEndPoint}, State: {connection.State}");
            }

            Console.WriteLine("\nGet UDP Listners");

            foreach (var connection in Udpconnections)
            {
                Console.WriteLine($"Local : {connection.Address.ToString()}: {connection.Port}");
            }

            Console.WriteLine("\nGet TCP Listners");
            foreach (var connection in netproperties.GetActiveTcpListeners())
            {
                Console.WriteLine($"Local : {connection.Address.ToString()}: {connection.Port}");
            }
        }
    }
}
