using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using static Network_Packet_Traffic.SocketViaAdmin.Socket_Monitor;

namespace Network_Packet_Traffic.SocketViaAdmin
{
    public struct IPHeader
    {
        public string IPSourceAddress;
        public string IPDestinationAddress;
        public Protocol Protocol;
        public int SourcePort;
        public int DestinationPort;

    }

    public delegate EventHandler<EventArgs> OnPacketReceived(object obj, IPHeader iPHeader);

    public class Socket_Monitor
    {
        Socket socket;
        private bool isListening = false;
        
        public event OnPacketReceived PacketReceived;

        public Socket_Monitor()
        {
           
            var he = Dns.GetHostEntry(Dns.GetHostName());
            var addr = he.AddressList.Where((h) => h.AddressFamily == AddressFamily.InterNetwork).ToList();
            try
            {
                socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            }
            catch
            {
                Console.Write("You need Administrator user privileges to execute this program.");
                return;
            }
            isListening = false;
            socket.Bind(new IPEndPoint(addr[0], 0));
            socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AcceptConnection, 1);

            byte[] ib = new byte[] { 1, 0, 0, 0 };
            byte[] ob = new byte[] { 0, 0, 0, 0 };
            socket.IOControl(IOControlCode.ReceiveAll, ib, ob);//SIO_RCVALL

        }

        public bool IsListening { get { return isListening; } }

        List<IPHeader> ipHeaderList = new List<IPHeader>();

        public IPHeader[] IPHeaders
        {
            get
            {
                return ipHeaderList.ToArray();
            }
        }

        public void StartListen()
        {
            if (!isListening)
            {
                isListening = true;
                ipHeaderList = new List<IPHeader>();
                Task.Run(() =>
                {
                    byte[] buf = new byte[4096];
                    while (isListening)
                    {
                        IAsyncResult iares = socket.BeginReceive(buf, 0, buf.Length, SocketFlags.None, null, null);
                        var len = socket.EndReceive(iares);
                        var sourcePort = (buf[20] << 8) + buf[21];
                        var destinationPort = (buf[22] << 8) + buf[23];
                        int m_HeaderLength = (buf[0] & 0x0F) * 4 /* sizeof(int) */;
                        var sourcePort1 = buf[m_HeaderLength] * 256 + buf[m_HeaderLength + 1];
                        var destinationPort1 = buf[m_HeaderLength + 2] * 256 + buf[m_HeaderLength + 3];
                        IPHeader iPHeader = new IPHeader();
                        iPHeader.IPSourceAddress = Ip(buf, 12);
                        iPHeader.IPDestinationAddress = Ip(buf, 16);
                        iPHeader.Protocol = (Protocol)buf[9];
                        iPHeader.SourcePort = sourcePort1;
                        iPHeader.DestinationPort = destinationPort1;
                        ipHeaderList.Add(iPHeader);
                        PacketReceived.Invoke(this, iPHeader);

                    }
                });
            }
            else
            {
                Console.WriteLine("Already listening.");
            }
        }

        public void StopListen()
        {
            if (isListening)
            {
                isListening = false;
                ipHeaderList.Clear();
                Console.WriteLine("Listening stopped.");
            }
            else
            {
                Console.WriteLine("Not currently listening.");
            }
        }

        private string Ip(byte[] buf, int i)
        {
            return string.Format("{0}.{1}.{2}.{3}", buf[i], buf[i + 1], buf[i + 2], buf[i + 3]);
        }

        private string Proto_V1(byte b)
        {
            switch (b)
            {
                case 1:
                    return "ICMP";
                case 2:
                    return "IGMP";
                case 3:
                    return "IPv6-ICMP"; // Adding a new protocol
                case 4:
                    return "IP";
                case 6:
                    return "TCP";
                case 17:
                    return "UDP";
                case 41:
                    return "IPv6";
                case 47:
                    return "GRE";
                case 50:
                    return "ESP";
                case 51:
                    return "AH";
                case 58:
                    return "IPv6-ICMP";
                case 80:
                    return "HTTP"; // Adding a new protocol
                case 88:
                    return "EIGRP";
                case 89:
                    return "OSP";
                case 112:
                    return "VRRP";
                case 115:
                    return "L2TP";
                case 121:
                    return "SCTP";
                case 132:
                    return "SCTP";
                case 135:
                    return "Mobility Header for IPv6";
                case 136:
                    return "ICMP for IPv6";
                case 137:
                    return "No Next Header for IPv6";
                case 138:
                    return "Destination Options for IPv6";
                case 139:
                    return "ICMP for IPv6";
                default:
                    return "Other";
            }
        }

        private string Proto_V2(byte b)
        {
            return Enum.GetName(typeof(Protocol), b);
        }

        #region Protocol

        public enum Protocol
        {
            HOPOPT = 0,
            ICMP = 1,
            IGMP = 2,
            GGP = 3,
            IP_in_IP = 4,
            ST = 5,
            TCP = 6,
            CBT = 7,
            EGP = 8,
            IGP = 9,
            BBN_RCC_MON = 10,
            NVP_II = 11,
            PUP = 12,
            ARGUS = 13,
            EMCON = 14,
            XNET = 15,
            CHAOS = 16,
            UDP = 17,
            MUX = 18,
            DCN_MEAS = 19,
            HMP = 20,
            PRM = 21,
            XNS_IDP = 22,
            TRUNK_1 = 23,
            TRUNK_2 = 24,
            LEAF_1 = 25,
            LEAF_2 = 26,
            RDP = 27,
            IRTP = 28,
            ISO_TP4 = 29,
            NETBLT = 30,
            MFE_NSP = 31,
            MERIT_INP = 32,
            DCCP = 33,
            _3PC = 34,
            IDPR = 35,
            XTP = 36,
            DDP = 37,
            IDPR_CMTP = 38,
            TPPlusPlus = 39,
            IL = 40,
            IPv6 = 41,
            SDRP = 42,
            IPv6_Route = 43,
            IPv6_Frag = 44,
            IDRP = 45,
            RSVP = 46,
            GREs = 47,
            DSR = 48,
            BNA = 49,
            ESP = 50,
            AH = 51,
            I_NLSP = 52,
            SWIPE = 53,
            NARP = 54,
            MOBILE = 55,
            TLSP = 56,
            SKIP = 57,
            IPv6_ICMP = 58,
            IPv6_NoNxt = 59,
            IPv6_Opts = 60,
            AHIP = 61,
            CFTP = 62,
            ALN = 63,
            SAT_EXPAK = 64,
            KRYPTOLAN = 65,
            RVD = 66,
            IPPC = 67,
            ADFS = 68,
            SAT_MON = 69,
            VISA = 70,
            IPCU = 71,
            CPNX = 72,
            CPHB = 73,
            WSN = 74,
            PVP = 75,
            BR_SAT_MON = 76,
            SUN_ND = 77,
            WB_MON = 78,
            WB_EXPAK = 79,
            ISO_IP = 80,
            VMTP = 81,
            SECURE_VMTP = 82,
            VINES = 83,
            TTP = 84,
            IPTM = 84,
            NSFNET_IGP = 85,
            DGP = 86,
            TCF = 87,
            EIGRP = 88,
            OSPF = 89,
            Sprite_RPC = 90,
            LARP = 91,
            MTP = 92,
            AX_25 = 93,
            OS = 94,
            MICP = 95,
            SCC_SP = 96,
            ETHERIP = 97,
            ENCAP = 98,
            APES = 99,
            GMTP = 100,
            IFMP = 101,
            PNNI = 102,
            PIM = 103,
            ARIS = 104,
            SCPS = 105,
            QNX = 106,
            A_N = 107,
            IPComp = 108,
            SNP = 109,
            Compaq_Peer = 110,
            IPX_in_IP = 111,
            VRRP = 112,
            PGM = 113,
            AHOP = 114,
            L2TP = 115,
            DDX = 116,
            IATP = 117,
            STP = 118,
            SRP = 119,
            UTI = 120,
            SMP = 121,
            SM = 122,
            PTP = 123,
            IS_IS_Over_IPv4 = 124,
            FIRE = 125,
            CRTP = 126,
            CRUDP = 127,
            SSCOPMCE = 128,
            IPLT = 129,
            SPS = 130,
            PIPE = 131,
            SCTP = 132,
            FC = 133,
            RSVP_E2E_IGNORE = 134,
            Mobility_Header = 135,
            UDPLite = 136,
            MPLS_in_IP = 137,
            manet = 138,
            HIP = 139,
            Shim6 = 140,
            WESP = 141,
            ROHC = 142,
            Unknown = -1
        }

        #endregion

    }
}
