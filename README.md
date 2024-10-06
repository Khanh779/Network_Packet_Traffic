# Network_Packet_Traffic

| Section                  | English                                                                                            | Tiếng Việt                                                                                                     |
|-------------------------|---------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------|
| **Description** <br> **(Mô tả)** | A network traffic monitoring application that captures and displays packet connections. | Ứng dụng giám sát lưu lượng mạng, bắt và hiển thị kết nối gói. |
| **Features** <br> **(Tính năng)** | &#8226; Analyze and display detailed network packet information. <br> &#8226; Support for TCP, UDP, and ARP protocols. <br> &#8226; Real-time monitoring of active and closed connections. <br> &#8226; Events for new and ended connections. | &#8226; Phân tích và hiển thị thông tin gói mạng chi tiết. <br> &#8226; Hỗ trợ giao thức TCP, UDP và ARP. <br> &#8226; Giám sát theo thời gian thực các kết nối đang hoạt động và đã đóng. <br> &#8226; Sự kiện cho các kết nối mới và đã kết thúc. |
| **Installation** <br> **(Cài đặt)** | &#8226; .NET Framework 4.7.2 or higher. <br> &#8226; Run as admin for full access. <br> &#8226; Use Visual Studio to build and run the project. | &#8226; Yêu cầu .NET Framework 4.7.2 hoặc cao hơn. <br> &#8226; Chạy với quyền quản trị để có quyền truy cập đầy đủ. <br> &#8226; Sử dụng Visual Studio để xây dựng và chạy dự án. |
| **Usage** <br> **(Sử dụng)** | &#8226; Use the `ConnectionsMonitor` class to listen for network packet changes. <br> &#8226; The tool automatically retrieves packet info and tracks ongoing traffic. | &#8226; Sử dụng lớp `ConnectionsMonitor` để lắng nghe sự thay đổi gói mạng. <br> &#8226; Công cụ tự động lấy thông tin gói và theo dõi lưu lượng đang diễn ra. |
| **Events** <br> **(Sự kiện)** | &#8226; `OnNewPacketConnectionStarted`: Triggered when a new connection starts. <br> &#8226; `OnNewPacketsConnectionLoad`: Lists all connections at once. <br> &#8226; `OnNewPacketConnectionEnded`: Triggered when a connection ends. | &#8226; `OnNewPacketConnectionStarted`: Kích hoạt khi một kết nối mới bắt đầu. <br> &#8226; `OnNewPacketsConnectionLoad`: Liệt kê tất cả các kết nối cùng lúc. <br> &#8226; `OnNewPacketConnectionEnded`: Kích hoạt khi một kết nối kết thúc. |
| **Contribution** <br> **(Đóng góp)** | Contributions are welcome! Create an Issue or Pull request with your ideas. | Sự đóng góp luôn được hoan nghênh! Tạo một Issue hoặc Pull request với ý tưởng của bạn. |
