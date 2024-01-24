using System;
using static Network_Packet_Traffic.ConnectionsExTable.IPHlpAPI32Wrapper;

namespace Network_Packet_Traffic.ConnectionExTable
{
    #region ICMP
    public struct IcmpInStatics
    {
        public int Messages { get; set; }
        public int Errors { get; set; }
        public int DestinationUnreachables { get; set; }
        public int TimeExceeded { get; set; }
        public int ParameterProblems { get; set; }
        public int SourceQuenchs { get; set; }
        public int Redirects { get; set; }
        public int Echos { get; set; }
        public int EchoReplies { get; set; }
        public int Timestamps { get; set; }
        public int TimestampReplies { get; set; }
        public string AddressMasks { get; set; }
        public int AddressMaskReplies { get; set; }
    }

    public struct IcmpOutStatics
    {
        public int Messages { get; set; }
        public int Errors { get; set; }
        public int DestinationUnreachables { get; set; }
        public int TimeExceeded { get; set; }
        public int ParameterProblems { get; set; }
        public int SourceQuenchs { get; set; }
        public int Redirects { get; set; }
        public int Echos { get; set; }
        public int EchoReplies { get; set; }
        public int Timestamps { get; set; }
        public int TimestampReplies { get; set; }
        public string AddressMasks { get; set; }
        public int AddressMaskReplies { get; set; }
    }

    public struct IcmpStatics
    {
        public IcmpInStatics In { get; set; }
        public IcmpOutStatics Out { get; set; }
    }
    #endregion

    public class ICMPConnection
    {

        MIB_ICMPINFO icmpInfo;

        public IcmpStatics IcmpConnectionStatics { get; set; }

        public ICMPConnection()
        {
            icmpInfo = LetGetIcmpStatistics();
            IcmpConnectionStatics = new IcmpStatics();
        }

        public void GetIcmpConnection()
        {
            // Lấy các thông số ICMP
            var a = IcmpConnectionStatics.In;
            a.Messages = icmpInfo.icmpInStats.dwMsgs;
            a.Errors = icmpInfo.icmpInStats.dwErrors;
            a.DestinationUnreachables = icmpInfo.icmpInStats.dwDestUnreachs;
            a.TimeExceeded = icmpInfo.icmpInStats.dwTimeExcds;
            a.ParameterProblems = icmpInfo.icmpInStats.dwParmProbs;
            a.SourceQuenchs = icmpInfo.icmpInStats.dwSrcQuenchs;
            a.Redirects = icmpInfo.icmpInStats.dwRedirects;
            a.Echos = icmpInfo.icmpInStats.dwEchos;
            a.EchoReplies = icmpInfo.icmpInStats.dwEchoReps;
            a.Timestamps = icmpInfo.icmpInStats.dwTimestamps;
            a.TimestampReplies = icmpInfo.icmpInStats.dwTimestampReps;
            a.AddressMasks = IntToSubnetMask(icmpInfo.icmpInStats.dwAddrMasks);
            a.AddressMaskReplies = icmpInfo.icmpInStats.dwAddrMaskReps;

            var b = IcmpConnectionStatics.Out;
            b.Messages = icmpInfo.icmpOutStats.dwMsgs;
            b.Errors = icmpInfo.icmpOutStats.dwErrors;
            b.DestinationUnreachables = icmpInfo.icmpOutStats.dwDestUnreachs;
            b.TimeExceeded = icmpInfo.icmpOutStats.dwTimeExcds;
            b.ParameterProblems = icmpInfo.icmpOutStats.dwParmProbs;
            b.SourceQuenchs = icmpInfo.icmpOutStats.dwSrcQuenchs;
            b.Redirects = icmpInfo.icmpOutStats.dwRedirects;
            b.Echos = icmpInfo.icmpOutStats.dwEchos;
            b.EchoReplies = icmpInfo.icmpOutStats.dwEchoReps;
            b.Timestamps = icmpInfo.icmpOutStats.dwTimestamps;
            b.TimestampReplies = icmpInfo.icmpOutStats.dwTimestampReps;
            b.AddressMasks = IntToSubnetMask(icmpInfo.icmpOutStats.dwAddrMasks);
            b.AddressMaskReplies = icmpInfo.icmpOutStats.dwAddrMaskReps;


        }



        MIB_ICMPINFO LetGetIcmpStatistics()
        {
            MIB_ICMPINFO icmpInfo = new MIB_ICMPINFO();

            int result = GetIcmpStatistics(ref icmpInfo);

            if (result != NO_ERROR)
            {
                // Handle the error if needed
                Console.WriteLine("Error getting ICMP statistics. Error code: " + result);
            }

            return icmpInfo;
        }

        string IntToSubnetMask(int intValue)
        {
            if (intValue < 0 || intValue > 32)
                throw new ArgumentException("Giá trị int phải nằm trong khoảng từ 0 đến 32.");

            string binaryString = Convert.ToString(intValue, 2);
            binaryString = binaryString.PadLeft(32, '0');
            string[] octets = new string[4];
            for (int i = 0; i < 4; i++)
                octets[i] = binaryString.Substring(i * 8, 8);
            string subnetMask = $"{Convert.ToInt32(octets[0], 2)}.{Convert.ToInt32(octets[1], 2)}.{Convert.ToInt32(octets[2], 2)}.{Convert.ToInt32(octets[3], 2)}";
            return subnetMask;
        }

    }
}
