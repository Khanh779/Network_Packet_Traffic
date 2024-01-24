using System;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using static Network_Packet_Traffic.ConnectionsExTable.IPHlpAPI32Wrapper;

namespace Network_Packet_Traffic.ConnectionsExTable
{

    #region Enum PacketConnectionInfo

    public struct PacketConnectionInfo
    {
        public string LocalAddress;
        public int LocalPort;
        public string RemoteAddress;
        public int RemotePort;
        public int ProcessId;
        public string State;
        public ProtocolType Protocol;
    }

    public enum ProtocolType
    {
        TCP,
        UDP,
        ICMP,
        ARP,
        Unknown
    }

    public enum StateType : uint
    {
        Closed,
        Listen,
        SynSent,
        SynReceived,
        Established,
        FinWait1,
        FinWait2,
        CloseWait,
        Closing,
        LastAck,
        TimeWait,
        DeleteTCB,

        Unknown
    }

    public enum MIB_IPNET_TYPE : int
    {
        Other = 1, //MIB_IPNET_TYPE_OTHER
        Invalid = 2, //MIB_IPNET_TYPE_INVALID
        Dynamic = 3, //MIB_IPNET_TYPE_DYNAMIC
        Static = 4 //MIB_IPNET_TYPE_STATIC
    }


    #endregion

    #region IPHlpAPI32Wrapper

    public class IPHlpAPI32Wrapper
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_ICMPSTATS
        {
            public int dwMsgs;
            public int dwErrors;
            public int dwDestUnreachs;
            public int dwTimeExcds;
            public int dwParmProbs;
            public int dwSrcQuenchs;
            public int dwRedirects;
            public int dwEchos;
            public int dwEchoReps;
            public int dwTimestamps;
            public int dwTimestampReps;
            public int dwAddrMasks;
            public int dwAddrMaskReps;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_ICMPINFO
        {
            public MIB_ICMPSTATS icmpInStats;
            public MIB_ICMPSTATS icmpOutStats;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_IPSTATS
        {
            public int dwForwarding;
            public int dwDefaultTTL;
            public int dwInReceives;
            public int dwInHdrErrors;
            public int dwInAddrErrors;
            public int dwForwDatagrams;
            public int dwInUnknownProtos;
            public int dwInDiscards;
            public int dwInDelivers;
            public int dwOutRequests;
            public int dwRoutingDiscards;
            public int dwOutDiscards;
            public int dwOutNoRoutes;
            public int dwReasmTimeout;
            public int dwReasmReqds;
            public int dwReasmOks;
            public int dwReasmFails;
            public int dwFragOks;
            public int dwFragFails;
            public int dwFragCreates;
            public int dwNumIf;
            public int dwNumAddr;
            public int dwNumRoutes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_IPNETTABLE
        {
            public int dwNumEntries;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 50)]
            public MIB_IPNETROW[] table;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_IPNETROW
        {
            public int dwIndex;
            public int dwPhysAddrLen;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 7)]
            public byte[] bPhysAddr;

            public int dwAddr;
            public int dwType;
        }


        public const byte NO_ERROR = 0;
        public const int FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100;
        public const int FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200;
        public const int FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000;

        public int dwFlags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS;


        public const byte MIB_TCP_RTO_CONSTANT = 2;
        public const byte MIB_TCP_RTO_OTHER = 1;
        public const byte MIB_TCP_RTO_RSRE = 3;
        public const byte MIB_TCP_RTO_VANJ = 4;

        [DllImport("iphlpapi.dll", SetLastError = true)]
        public static extern int GetUdpTable(byte[] pUdpTable, out int pdwSize, bool bOrder);

        [DllImport("iphlpapi.dll")]
        public extern static int GetIcmpStatistics(ref MIB_ICMPINFO pStats);


        [DllImport("iphlpapi.dll")]
        public extern static int GetIpStatistics(ref MIB_IPSTATS pStats);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        public extern static int GetIpNetTable(ref MIB_IPNETTABLE pTable, long PULONG, bool bOrder);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        public static extern int GetIpNetTable(IntPtr pIpNetTable, ref int pdwSize, bool bOrder);


        [DllImport("iphlpapi.dll", SetLastError = true)]
        public static extern int GetTcpTable(byte[] pTcpTable, out int pdwSize, bool bOrder);

        [DllImport("kernel32.dll")]
        private static extern int FormatMessage(int flags, IntPtr source, int messageId,
            int languageId, StringBuilder buffer, int size, IntPtr arguments);

        public static string GetAPIErrorMessageDescription(int ApiErrNumber)
        {
            StringBuilder sError = new StringBuilder(512);
            int lErrorMessageLength;
            lErrorMessageLength = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, IntPtr.Zero, ApiErrNumber, 0, sError, sError.Capacity, IntPtr.Zero);

            if (lErrorMessageLength > 0)
            {
                string strgError = sError.ToString();
                strgError = strgError.Substring(0, strgError.Length - 2);
                return strgError + " (" + ApiErrNumber.ToString() + ")";
            }
            return "none";
        }

        public enum UDP_TABLE_CLASS
        {
            UDP_TABLE_BASIC,
            UDP_TABLE_OWNER_PID,
            UDP_TABLE_OWNER_MODULE
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_UDPROW_OWNER_PID
        {
            //public uint dwLocalAddr;
            //public int dwLocalPort;
            //public int dwOwningPid;

            public uint dwLocalAddr;
            public int dwLocalPort;
            public uint dwRemoteAddr; // Địa chỉ remote
            public int dwRemotePort; // Cổng remote
            public int dwOwningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_UDPTABLE_OWNER_PID
        {
            public uint dwNumEntries;
            public MIB_UDPROW_OWNER_PID[] table;
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        public static extern int GetExtendedUdpTable(IntPtr pUdpTable, ref int pdwSize, bool bOrder, int ulAf, UDP_TABLE_CLASS TableClass, uint reserved);

        public enum TCP_TABLE_CLASS
        {
            TCP_TABLE_BASIC_LISTENER,
            TCP_TABLE_BASIC_CONNECTIONS,
            TCP_TABLE_BASIC_ALL,
            TCP_TABLE_OWNER_PID_LISTENER,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            TCP_TABLE_OWNER_PID_ALL,
            TCP_TABLE_OWNER_MODULE_LISTENER,
            TCP_TABLE_OWNER_MODULE_CONNECTIONS,
            TCP_TABLE_OWNER_MODULE_ALL
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPTABLE_OWNER_PID
        {
            public uint dwNumEntries;
            public MIB_TCPROW_OWNER_PID[] table;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPROW_OWNER_PID
        {
            public uint dwState;
            public uint dwLocalAddr;
            public int dwLocalPort;
            public uint dwRemoteAddr;
            public int dwRemotePort;
            public int dwOwningPid;
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        public static extern int GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, TCP_TABLE_CLASS TableClass, uint reserved);


        [DllImport("iphlpapi.dll", SetLastError = true)]
        public extern static int AllocateAndGetTcpExTableFromStack(ref IntPtr pTable, bool bOrder, IntPtr heap, int zero, int flags);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        public extern static int AllocateAndGetUdpExTableFromStack(ref IntPtr pTable, bool bOrder, IntPtr heap, int zero, int flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetProcessHeap();

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_UDPSTATS
        {
            public int dwInDatagrams;
            public int dwNoPorts;
            public int dwInErrors;
            public int dwOutDatagrams;
            public int dwNumAddrs;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPSTATS
        {
            public int dwRtoAlgorithm;
            public int dwRtoMin;
            public int dwRtoMax;
            public int dwMaxConn;
            public int dwActiveOpens;
            public int dwPassiveOpens;
            public int dwAttemptFails;
            public int dwEstabResets;
            public int dwCurrEstab;
            public int dwInSegs;
            public int dwOutSegs;
            public int dwRetransSegs;
            public int dwInErrs;
            public int dwOutRsts;
            public int dwNumConns;
        }

        [DllImport("iphlpapi.dll")]
        public extern static int GetUdpStatistics(ref MIB_UDPSTATS pStats);

        [DllImport("iphlpapi.dll")]
        public extern static int GetTcpStatistics(ref MIB_TCPSTATS pStats);


    }

    #endregion

    public delegate void OnNewPacketsConnectionLoad(object ob, PacketConnectionInfo[] packet); // Liệt kê tất cả các gói
    public delegate void OnNewPacketConnectionStarted(object ob, PacketConnectionInfo packet); // Liệt kê các gói mới đã bắt đầu kết nối
    public delegate void OnNewPacketConnectionEnded(object ob, PacketConnectionInfo packet); // Liệt kê các gói mới đã kết thúc kết nối

    public class ConnectionsMonitor
    {
        private const int NO_ERROR = 0;


        public event OnNewPacketConnectionStarted OnNewPacketConnectionStarted;
        public event OnNewPacketsConnectionLoad OnNewPacketsConnectionLoad;
        public event OnNewPacketConnectionEnded OnNewPacketConnectionEnded;

        PacketConnectionInfo[] _oldPackets = new PacketConnectionInfo[0];

        Thread task = null;

        public ConnectionsMonitor(bool autoReload = true)
        {
            task = new Thread(GetAllPacket);
            IsAutoReload = autoReload;
            task.IsBackground = true;
        }

        public bool IsAutoReload { get; set; } = true;

        public void StartListen()
        {
            // Gọi các phương thức để lấy thông tin và xử lý nó ở đây
            if (task != null && task.ThreadState != ThreadState.Running)
                task.Start();
        }

        public bool IsRunning
        {
            get { return task.ThreadState == ThreadState.Running; }
        }

        public void StopListen()
        {
            // Đối với các tác vụ dừng lắng nghe, bạn có thể thực hiện các bước tương ứng ở đây
            if (task.ThreadState == ThreadState.Running)
                task.Abort();
        }

        #region Connection Table

        void GetAllPacket()
        {
            do
            {
                MIB_TCPTABLE_OWNER_PID tcpTable = GetTcpTable();
                MIB_UDPTABLE_OWNER_PID udpTable = GetUdpTable();
                MIB_IPNETTABLE mIB_IPNETTABLE = GetArpTable();
                PacketConnectionInfo[] packetConnectionInfos = new PacketConnectionInfo[tcpTable.dwNumEntries + udpTable.dwNumEntries + mIB_IPNETTABLE.dwNumEntries];
                for (int i = 0; i < tcpTable.dwNumEntries; i++)
                {
                    MIB_TCPROW_OWNER_PID tcpRow = tcpTable.table[i];

                    PacketConnectionInfo packet = new PacketConnectionInfo();
                    packet.LocalAddress = ConvertIpAddress((int)tcpRow.dwLocalAddr).ToString();
                    packet.LocalPort = tcpRow.dwLocalPort;
                    packet.RemoteAddress = ConvertIpAddress((int)tcpRow.dwRemoteAddr).ToString();
                    packet.RemotePort = tcpRow.dwRemotePort;
                    packet.ProcessId = tcpRow.dwOwningPid;
                    packet.Protocol = ProtocolType.TCP;
                    packet.State = (GetState(tcpRow.dwState)).ToString();
                    packetConnectionInfos[i] = packet;
                }


                for (int i = 0; i < udpTable.dwNumEntries; i++)
                {
                    MIB_UDPROW_OWNER_PID udpRow = udpTable.table[i];
                    PacketConnectionInfo packet = new PacketConnectionInfo();
                    packet.LocalAddress = ConvertIpAddress((int)udpRow.dwLocalAddr).ToString();
                    packet.LocalPort = udpRow.dwLocalPort;
                    packet.RemoteAddress = ConvertIpAddress((int)udpRow.dwRemoteAddr).ToString();
                    packet.RemotePort = udpRow.dwRemotePort;
                    packet.State = GetState(12).ToString();
                    packet.ProcessId = udpRow.dwOwningPid;
                    packet.Protocol = ProtocolType.UDP;
                    packetConnectionInfos[i + tcpTable.dwNumEntries] = packet;

                }

                for (int i = 0; i < mIB_IPNETTABLE.dwNumEntries; i++)
                {
                    MIB_IPNETROW arpRow = mIB_IPNETTABLE.table[i];
                    PacketConnectionInfo packet = new PacketConnectionInfo();
                    packet.LocalAddress = ConvertIpAddress(arpRow.dwAddr).ToString();
                    packet.LocalPort = 0;
                    packet.RemoteAddress = ConvertIpAddress(arpRow.dwPhysAddrLen).ToString();
                    packet.RemotePort = 0;
                    packet.State = GetState(12).ToString();
                    packet.ProcessId = 0;
                    packet.Protocol = ProtocolType.ARP;
                    packetConnectionInfos[i + tcpTable.dwNumEntries + udpTable.dwNumEntries] = packet;
                }

                OnNewPacketsConnectionLoad?.Invoke(this, packetConnectionInfos);

                // Kiểm tra nếu các gói đã lấy trước đó mà vẫn còn tồn tại trong _oldPackets thì bỏ qua, nếu không thì gọi sự kiện OnNewPacketConnectionStarted
                packetConnectionInfos.ToList().ForEach(x =>
                {
                    if (!_oldPackets.Contains(x))
                    {
                        OnNewPacketConnectionStarted?.Invoke(this, x);
                    }

                });

                // Kiểm tra gói cũ mà không có trong gói mới thì gọi sự kiện OnNewPacketConnectionEnded

                _oldPackets.ToList().ForEach(x =>
                {
                    if (!packetConnectionInfos.Contains(x))
                        OnNewPacketConnectionEnded?.Invoke(this, x);
                });

                Thread.Sleep(5000);
                _oldPackets = packetConnectionInfos;
            }
            while (IsAutoReload);

        }


        public void GetTcp()
        {
            MIB_TCPTABLE_OWNER_PID tcpTable = GetTcpTable();

            Console.WriteLine("TCP Table:");
            Console.WriteLine($"Number of entries: {tcpTable.dwNumEntries}");

            foreach (MIB_TCPROW_OWNER_PID tcpRow in tcpTable.table)
            {
                Console.WriteLine($"State: {GetState(tcpRow.dwState)}");
                Console.WriteLine($"Local Address: {ConvertIpAddress((int)tcpRow.dwLocalAddr)}:{tcpRow.dwLocalPort}");
                Console.WriteLine($"Remote Address: {ConvertIpAddress((int)tcpRow.dwRemoteAddr)}:{tcpRow.dwRemotePort}");
                Console.WriteLine($"Process ID: {tcpRow.dwOwningPid}");
                Console.WriteLine();
            }
        }

        public void GetUdp()
        {
            MIB_UDPTABLE_OWNER_PID udpTable = GetUdpTable();

            Console.WriteLine("UDP Table:");
            Console.WriteLine($"Number of entries: {udpTable.dwNumEntries}");

            foreach (MIB_UDPROW_OWNER_PID udpRow in udpTable.table)
            {
                Console.WriteLine($"Local Address: {ConvertIpAddress((int)udpRow.dwLocalAddr)}:{udpRow.dwLocalPort}");
                Console.WriteLine($"Process ID: {udpRow.dwOwningPid}");
                Console.WriteLine();
            }
        }

        #endregion

        //Lấy thông tin UDP và TCP có hiện Process ID dùng MIB_TCPROW_OWNER_PID[] và MIB_UDPROW_OWNER_PID[]

        #region GetConnectionExTable

        MIB_TCPTABLE_OWNER_PID GetTcpTable()
        {
            MIB_TCPTABLE_OWNER_PID tcpTable = new MIB_TCPTABLE_OWNER_PID();
            int buffSize = 0;
            int ret = GetExtendedTcpTable(IntPtr.Zero, ref buffSize, true, 2, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
            IntPtr buffTable = Marshal.AllocHGlobal(buffSize);

            try
            {
                ret = GetExtendedTcpTable(buffTable, ref buffSize, true, 2, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
                if (ret != NO_ERROR)
                {
                    return tcpTable;
                }

                tcpTable.dwNumEntries = (uint)Marshal.ReadIntPtr(buffTable);
                IntPtr buffTablePointer = (IntPtr)((long)buffTable + Marshal.SizeOf(typeof(uint)));
                MIB_TCPROW_OWNER_PID[] tcpRows = new MIB_TCPROW_OWNER_PID[tcpTable.dwNumEntries];

                for (int i = 0; i < tcpTable.dwNumEntries; i++)
                {
                    tcpRows[i] = (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(buffTablePointer, typeof(MIB_TCPROW_OWNER_PID));
                    buffTablePointer += Marshal.SizeOf(tcpRows[i]);
                }

                tcpTable.table = tcpRows;
            }
            finally
            {
                Marshal.FreeHGlobal(buffTable);
            }

            return tcpTable;
        }

        MIB_UDPTABLE_OWNER_PID GetUdpTable()
        {
            MIB_UDPTABLE_OWNER_PID udpTable = new MIB_UDPTABLE_OWNER_PID();
            int buffSize = 0;
            int ret = GetExtendedUdpTable(IntPtr.Zero, ref buffSize, true, 2, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
            IntPtr buffTable = Marshal.AllocHGlobal(buffSize);

            try
            {
                ret = GetExtendedUdpTable(buffTable, ref buffSize, true, 2, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
                if (ret != NO_ERROR)
                {
                    return udpTable;
                }

                udpTable.dwNumEntries = (uint)Marshal.ReadIntPtr(buffTable);

                IntPtr buffTablePointer = buffTable + Marshal.SizeOf(udpTable.dwNumEntries);
                MIB_UDPROW_OWNER_PID[] udpRows = new MIB_UDPROW_OWNER_PID[udpTable.dwNumEntries];

                for (int i = 0; i < udpTable.dwNumEntries; i++)
                {
                    udpRows[i] = (MIB_UDPROW_OWNER_PID)Marshal.PtrToStructure(buffTablePointer, typeof(MIB_UDPROW_OWNER_PID));
                    buffTablePointer += Marshal.SizeOf(udpRows[i]);
                }

                udpTable.table = udpRows;
            }
            finally
            {
                Marshal.FreeHGlobal(buffTable);
            }

            return udpTable;
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

        #endregion

        public StateType GetState(uint numState)
        {
            // Nếu tồn tại số uint strong trong enum StateType thì trả về giá trị tương ứng, ngược lại, trả về Unknown
            if (Enum.IsDefined(typeof(StateType), numState))
                return (StateType)numState;
            else
                return StateType.Unknown;
        }

        private IPAddress ConvertIpAddress(int ipAddress)
        {

            byte[] ipBytes = BitConverter.GetBytes(ipAddress);
            Array.Reverse(ipBytes);
            return new IPAddress(ipBytes);
        }
    }
}
