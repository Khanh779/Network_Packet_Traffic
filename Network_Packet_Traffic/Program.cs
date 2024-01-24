using Network_Packet_Traffic.ConnectionsExTable;
using System;
using System.Windows.Forms;

namespace Network_Packet_Traffic
{
    internal static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        //[STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            //Application.Run(new Form1());

            //SocketViaAdmin.Socket_Monitor sm = new SocketViaAdmin.Socket_Monitor();
            //sm.StartListen();

            //TcpUdpConnectionInformation.TCPUDPInformation tcp = new TcpUdpConnectionInformation.TCPUDPInformation();
            //tcp.Start();

            ConnectionsExTable.ConnectionsMonitor ex = new ConnectionsExTable.ConnectionsMonitor();
            //ex.GetArp();
            //ex.GetTcp();
            //ex.GetUdp();
            //ex.GetICMPInfo();
            //ex.GetIPStatics();

            ex.OnNewPacketsConnectionLoad += Ex_OnNewPacketsConnectionLoad;
            ex.OnNewPacketConnectionEnded += Ex_OnNewPacketConnectionEnded;
            ex.OnNewPacketConnectionStarted += Ex_OnNewPacketConnectionStarted;
            ex.IsAutoReload = true;
            ex.StartListen();

            Application.Run();
        }

        static int i = 0;

        private static void Ex_OnNewPacketConnectionStarted(object ob, PacketConnectionInfo packet)
        {
            Console.WriteLine("Started ID: " + packet.ProcessId + " Local: " + packet.LocalAddress + ":" + packet.LocalPort + " Remote: " + packet.RemoteAddress + ":" + packet.RemotePort
                + " State: " + packet.State + " Protocol: " + packet.Protocol);
            Console.WriteLine("\nKiem tra lan: " + i);
        }

        private static void Ex_OnNewPacketConnectionEnded(object ob, PacketConnectionInfo packet)
        {
            Console.WriteLine("Ended ID: " + packet.ProcessId + " Local: " + packet.LocalAddress + ":" + packet.LocalPort + " Remote: " + packet.RemoteAddress + ":" + packet.RemotePort
                + " State: " + packet.State + " Protocol: " + packet.Protocol);
            Console.WriteLine("\nKiem tra lan: " + i);
        }

        private static void Ex_OnNewPacketsConnectionLoad(object ob, PacketConnectionInfo[] packet)
        {
            i++;
            Console.Clear();
            foreach (var item in packet)
            {
                Console.WriteLine("ID: " + item.ProcessId + " Local: " + item.LocalAddress + ":" + item.LocalPort + " Remote: " + item.RemoteAddress + ":" + item.RemotePort + " State: "
                    + item.State + " Protocol: " + item.Protocol);
            }
            Console.WriteLine($"Kiem tra lan: {i} Total: " + packet.Length);
            Console.WriteLine("\n===");
        }



    }
}