using Network_Packet_Traffic.ConnectionsExTable;
using System;
using System.Net;
using System.Runtime.InteropServices;
using static Network_Packet_Traffic.ConnectionsExTable.IPHlpAPI32Wrapper;

namespace Network_Packet_Traffic.ConnectionExTable
{

    public partial class ARPConnection
    {
        public struct ARPInfo
        {
            public ForwardingStatus Forwarding { get; set; }
            public int DefaultTTL { get; set; }
            public int InReceives { get; set; }
            public int InHeaderErrors { get; set; }
            public int InAddressErrors { get; set; }
            public int ForwardedDatagrams { get; set; }
            public int InUnknownProtocols { get; set; }
            public int InDiscards { get; set; }
            public int InDelivers { get; set; }
            public RequestsStatus OutRequests { get; set; }
            public int RoutingDiscards { get; set; }
            public int OutDiscards { get; set; }
            public int OutNoRoutes { get; set; }
            public int ReassemblyTimeout { get; set; }
            public RequestsStatus ReassemblyRequests { get; set; }
            public int ReassemblyOks { get; set; }
            public int ReassemblyFails { get; set; }
            public int FragmentOks { get; set; }
            public int FragmentFails { get; set; }
            public int FragmentCreates { get; set; }
            public int NumberOfInterfaces { get; set; }
            public int NumberOfAddresses { get; set; }
            public int NumberOfRoutes { get; set; }
        }

        public struct ARPTableInfo
        {
            public int NumberOfEntries { get; set; }
            public ARPConnectionInfo[] ARPConnections { get; set; }


        }

        public enum ForwardingStatus : int
        {
            NonForwarding = 0,
            Forwarding = 1,
            Router = 2
        }

        public enum RequestsStatus
        {
            No = 0,
            Low = 1,
            Medium = 2,
            High = 3
        }

        public class ARPConnectionInfo
        {
            public int Index { get; set; }
            public int PhysicalAddressLength { get; set; }
            public byte[] PhysicalAddress { get; set; }
            public IPAddress Address { get; set; }
            public MIB_IPNET_TYPE Type { get; set; }

        }

        MIB_IPSTATS iB_IPSTATS;
        MIB_IPNETTABLE mIB_IPNETTABLE;

        public ARPConnection()
        {
            iB_IPSTATS = GetIpStas();
            mIB_IPNETTABLE = GetArpTable();
        }

        public ARPInfo GetARP()
        {

            ARPInfo a = new ARPInfo();
            a.DefaultTTL = iB_IPSTATS.dwDefaultTTL;
            a.ForwardedDatagrams = iB_IPSTATS.dwForwDatagrams;
            a.Forwarding = (ForwardingStatus)iB_IPSTATS.dwForwarding;
            a.FragmentCreates = iB_IPSTATS.dwFragCreates;
            a.FragmentFails = iB_IPSTATS.dwFragFails;
            a.FragmentOks = iB_IPSTATS.dwFragOks;
            a.InAddressErrors = iB_IPSTATS.dwInAddrErrors;
            a.InDelivers = iB_IPSTATS.dwInDelivers;
            a.InDiscards = iB_IPSTATS.dwInDiscards;
            a.InHeaderErrors = iB_IPSTATS.dwInHdrErrors;
            a.InReceives = iB_IPSTATS.dwInReceives;
            a.InUnknownProtocols = iB_IPSTATS.dwInUnknownProtos;
            a.NumberOfAddresses = iB_IPSTATS.dwNumAddr;
            a.NumberOfInterfaces = iB_IPSTATS.dwNumIf;
            a.NumberOfRoutes = iB_IPSTATS.dwNumRoutes;
            a.OutDiscards = iB_IPSTATS.dwOutDiscards;
            a.OutNoRoutes = iB_IPSTATS.dwOutNoRoutes;
            a.OutRequests = (RequestsStatus)iB_IPSTATS.dwOutRequests;
            a.ReassemblyFails = iB_IPSTATS.dwReasmFails;
            a.ReassemblyOks = iB_IPSTATS.dwReasmOks;
            a.ReassemblyRequests = (RequestsStatus)iB_IPSTATS.dwReasmReqds;
            a.ReassemblyTimeout = iB_IPSTATS.dwReasmTimeout;
            a.RoutingDiscards = iB_IPSTATS.dwRoutingDiscards;
            return a;

        }

        public ARPTableInfo GetARPTable()
        {
            ARPTableInfo a = new ARPTableInfo();
            MIB_IPNETTABLE b = GetArpTable();
            a.NumberOfEntries = mIB_IPNETTABLE.dwNumEntries;
            a.ARPConnections = new ConnectionExTable.ARPConnection.ARPConnectionInfo[a.NumberOfEntries];
            for (int i = 0; i < a.NumberOfEntries; i++)
            {
                a.ARPConnections[i] = new ConnectionExTable.ARPConnection.ARPConnectionInfo();
                a.ARPConnections[i].Index = mIB_IPNETTABLE.table[i].dwIndex;
                a.ARPConnections[i].PhysicalAddressLength = mIB_IPNETTABLE.table[i].dwPhysAddrLen;
                a.ARPConnections[i].PhysicalAddress = mIB_IPNETTABLE.table[i].bPhysAddr;
                a.ARPConnections[i].Address = ConvertIpAddress(mIB_IPNETTABLE.table[i].dwAddr);
                a.ARPConnections[i].Type = (MIB_IPNET_TYPE)b.table[i].dwType;
            }
            return a;
        }

        MIB_IPSTATS GetIpStas()
        {
            MIB_IPSTATS ipStats = new MIB_IPSTATS();

            int result = GetIpStatistics(ref ipStats);

            if (result != NO_ERROR)
            {
                // Handle the error if needed
                Console.WriteLine("Error getting IP statistics. Error code: " + result);
            }

            return ipStats;
        }

        MIB_IPNETTABLE GetArpTable()
        {
            MIB_IPNETTABLE arpTable = new MIB_IPNETTABLE();

            int buffSize = 0;
            int result = GetIpNetTable(IntPtr.Zero, ref buffSize, false);
            IntPtr buffTable = Marshal.AllocHGlobal(buffSize);

            try
            {
                result = GetIpNetTable(buffTable, ref buffSize, false);

                if (result != NO_ERROR)
                {
                    Console.WriteLine("Error getting ARP table. Error code: " + result);
                    return arpTable;
                }

                arpTable = (MIB_IPNETTABLE)Marshal.PtrToStructure(buffTable, typeof(MIB_IPNETTABLE));
                arpTable.table = new MIB_IPNETROW[arpTable.dwNumEntries];

                IntPtr buffTablePointer = buffTable + Marshal.SizeOf(arpTable.dwNumEntries);

                for (int i = 0; i < arpTable.dwNumEntries; i++)
                {
                    arpTable.table[i] = (MIB_IPNETROW)Marshal.PtrToStructure(buffTablePointer, typeof(MIB_IPNETROW));
                    buffTablePointer += Marshal.SizeOf(arpTable.table[i]);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffTable);
            }

            return arpTable;
        }



        private IPAddress ConvertIpAddress(int ipAddress)
        {

            byte[] ipBytes = BitConverter.GetBytes(ipAddress);
            Array.Reverse(ipBytes);
            return new IPAddress(ipBytes);
        }
    }
}
