using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Network_Packet_Traffic.ConnectionsInformation
{
    public class GetConnectionsInformation
    {
        IPGlobalProperties netproperties;
        IPGlobalStatistics ipstatisticsV4;
        IPGlobalStatistics ipstatisticsV6;

        NetworkInterface[] networkInterfaces;
        IPInterfaceStatistics interfaceStatistics;

        TcpStatistics tcpStatisticsV4;
        TcpStatistics tcpStatisticsV6;
        UdpStatistics udpStatisticsV4;
        UdpStatistics udpStatisticsV6;

        IcmpV4Statistics icmpV4Statistics;
        IcmpV6Statistics icmpV6Statistics;

        TcpConnectionInformation[] tcpConnections;

        public GetConnectionsInformation()
        {
            netproperties = IPGlobalProperties.GetIPGlobalProperties();

            ipstatisticsV4 = netproperties.GetIPv4GlobalStatistics();
            ipstatisticsV6 = netproperties.GetIPv6GlobalStatistics();
            
            tcpStatisticsV4 = netproperties.GetTcpIPv4Statistics();
            tcpStatisticsV6 = netproperties.GetTcpIPv6Statistics();
            tcpConnections = netproperties.GetActiveTcpConnections(); // GetActiveTcpConnections() is a method of IPGlobalProperties class
            udpStatisticsV4 = netproperties.GetUdpIPv4Statistics();
            udpStatisticsV6 = netproperties.GetUdpIPv6Statistics();
            
            icmpV4Statistics = netproperties.GetIcmpV4Statistics();
            icmpV6Statistics = netproperties.GetIcmpV6Statistics();

            networkInterfaces = NetworkInterface.GetAllNetworkInterfaces(); 

        }

        /// <summary>
        /// Get the Active TCP Lirsteners
        /// </summary>
        /// <returns></returns>
        public IPEndPoint[] GetActiveTcpListeners()
        {
            return netproperties.GetActiveTcpListeners();
        }

        /// <summary>
        /// Get the Active UDP Listeners
        /// </summary>
        /// <returns></returns>
        public IPEndPoint[] GetActiveUdpListeners()
        {
            return netproperties.GetActiveUdpListeners();
        }

        /// <summary>
        /// Get the TCP Connections
        /// </summary>
        /// <returns></returns>
        public TcpConnectionInformation[] GetTcpConnections()
        {
            return tcpConnections;
        }

        /// <summary>
        /// Get the Network Interfaces
        /// </summary>
        /// <param name="index"></param>
        /// <returns></returns>
        public IPInterfaceStatistics GetIPInterfaceStatistics(int index)
        {
            IPInterfaceStatistics da= networkInterfaces[index].GetIPStatistics();
            return da;
        }

        /// <summary>
        /// Get the IP Interface Properties
        /// </summary>
        /// <param name="index"></param>
        /// <returns></returns>
        public IPInterfaceProperties GetIPInterfaceProperties(int index)
        {
            IPInterfaceProperties da = networkInterfaces[index].GetIPProperties();
            return da;
        }

        /// <summary>
        /// Get the IPv4 Interface Properties
        /// </summary>
        /// <param name="index"></param>
        /// <returns></returns>
        public IPv4InterfaceStatistics GetIPv4InterfaceProperties(int index)
        {
            var da = networkInterfaces[index].GetIPv4Statistics();
            return da;
        }

        /// <summary>
        /// Get the TCP V4 Statistics
        /// </summary>
        /// <returns></returns>
        public TcpStatistics GetTcpV4Statistics()
        {
            return tcpStatisticsV4;
        }

        /// <summary>
        /// Get the TCP V6 Statistics
        /// </summary>
        /// <returns></returns>        
        public TcpStatistics GetTcpV6Statistics()
        {
            return tcpStatisticsV6;
        }

        /// <summary>
        /// Get the UDP V4 Statistics
        /// </summary>
        /// <returns></returns>
        public UdpStatistics GetUdpV4Statistics()
        {
            return udpStatisticsV4;
        }

        /// <summary>
        /// Get the UDP V6 Statistics
        /// </summary>
        /// <returns></returns>
        public UdpStatistics GetUdpV6Statistics()
        {
            return udpStatisticsV6;
        }

       /// <summary>
       /// Get the IP Statistics V4
       /// </summary>
       /// <returns></returns>
        public IPGlobalStatistics GetIPV4Statistics()
        {
            return ipstatisticsV4;
        }

        /// <summary>
        /// Get the IP Statistics V6
        /// </summary>
        /// <returns></returns>
        public IPGlobalStatistics GetIPV6Statistics()
        {
            return ipstatisticsV6;
        }
        
       
        /// <summary>
        /// Get the ICMP V4 Statistics
        /// </summary>
        /// <returns></returns>
        public IcmpV4Statistics GetIcmpV4Statistics()
        {
            return icmpV4Statistics;
        }

        /// <summary>
        /// Get the ICMP V6 Statistics
        /// </summary>
        /// <returns></returns>
        public IcmpV6Statistics GetIcmpV6Statistics()
        {
            return icmpV6Statistics;
        }


    }
}
