# Báo cáo về các giao thức mạng.


## 1. Giao thức DHCP.
#### 1.1 Lý Thuyết
DHCP là giao thức cấu hình máy chủ tự động. Giao thức này cho phép việc cấp phát các địa chỉ IP cùng các cấu hình liên quan khác một cách tự động, làm giảm sự can thiệp vào hệ thống mạng cũng như tránh tình trạng trùng IP.
#### 1.2 Nguyên Tắc Hoạt động
DHCP sẽ tự động quản lý các địa chỉ IP, tự động gán các IP chưa được sử dụng từ một ***pool*** các IP mà DHCP có sẵn đến các thiết bị kết nối tới mạng theo một khoảng thời gian .
#### 1.3 Các bước hoạt động
Khi một máy tính khởi động và không có địa chỉ IP, nó sẽ broadcast một giao thức bootstrap ***bootstrap protocol*** nhằm tìm đến DHCP server có tên gọi là DHCP discover.
![](https://github.com/kidluc/NETWORKREPORT/blob/master/Screenshot%20from%202017-09-06%2008-41-35.png)
DHCP sau khi nhận được DHCP discover, DHCP sẽ trả về một DHCP offer có chứa IP và các thông tin cấu hình tự động từ trong ***pool*** của mình về máy tính.
![](https://github.com/kidluc/NETWORKREPORT/blob/master/Screenshot%20from%202017-09-06%2008-43-45.png)
Nếu máy tính đồng ý, máy tính sẽ gửi một thông điệp là DHCP request để xác nhận việc sử dụng IP và các thông tin trong gói DHCP offer từ DHCP server.
![](https://github.com/kidluc/NETWORKREPORT/blob/master/Screenshot%20from%202017-09-06%2008-44-21.png)
Cuối cùng, DHCP sẽ gửi một thông điệp DHCP ACK để xác nhận điều đó. Điều này có nghĩa là máy tính và các DHCP server khác sẽ xác nhận là IP đã được sử dụng.
![](https://github.com/kidluc/NETWORKREPORT/blob/master/Screenshot%20from%202017-09-06%2008-44-37.png)
#### 1.4 Mô hình lab

![](https://github.com/kidluc/NETWORKREPORT/blob/master/Screenshot%20from%202017-09-07%2008-33-59.png)

#### 1.5 Cấu hình các phần mềm DHCP server.
Cấu hình phần mềm DHCP sau đây được sử dụng trên bản ubuntu 16.04.

**B0** 
Set IP tĩnh cho máy
```
auto ens33
iface ens33 inet static
  address 192.168.174.129
  netmask 255.255.255.0
  gateway 192.168.174.1
  broadcast 192.168.174.255
  ```

**B1** 
Install package isc-dhcp-server: sudo apt install isc-dhcp-server

**B2**
Sau khi cấu hình xong, ta mở ifconfig lên để lấy thông tin về interfaces và IP.

**B3**
Cấu hình file isc-dhcp-server để chỉ định interface release IP và các thông tin cho client.
Edit file **/etc/default/isc-dhcp-server** như dưới.

```sh
INTERFACES=  "ens33"  # "your-interfaces-in-ifconfig"
```
**B4**
Cấu hình file **/etc/dhcp/dhcpd.conf**

```sh
# The ddns-updates-style parameter controls whether or not the server will
# attempt to do a DNS update when a lease is confirmed. We default to the
# behavior of the version 2 packages ('none', since DHCP v2 didn't
# have support for DDNS.)
ddns-update-style none;

# option definitions common to all supported networks...
option domain-name "192.168.174.129";
option domain-name-servers 8.8.8.8;

default-lease-time 600;
max-lease-time 7200;

# If this DHCP server is the official DHCP server for the local
# network, the authoritative directive should be uncommented.
authoritative;

# Use this to send dhcp log messages to a different log file (you also
# have to hack syslog.conf to complete the redirection).
log-facility local7;
```

Thêm vào phần cấu hình chính của DHCP server cũng trong file đó.

```sh
# A slightly different configuration for an internal subnet.
subnet 192.168.174.0 netmask 255.255.255.0 {
  range 192.168.174.20 192.168.174.30;
  option routers 192.168.174.1;
  option broadcast-address 192.168.174.255;
  default-lease-time 600;
  max-lease-time 7200;
}

```

## 2. Giao thức DNS
#### 2.1 Lý Thuyết
DNS (Domain name service) là giao thức giúp cho việc chuyển đổi tên miền mà con người dễ ghi nhớ sang địa chỉ IP vật lý của tên miền đó. DNS giúp liên kết với các trang thiết bị mạng cho các mục đích định vị và địa chỉ hóa các thiết bị trên Internet.

Hệ thống tên miền phân phối trách nhiệm gán tên miền và lập bản đồ những tên tới địa chỉ IP bằng cách định rõ những máy chủ có thẩm quyền cho mỗi tên miền. Những máy chủ có tên thẩm quyền được phân công chịu trách nhiệm đối với tên miền riêng của họ, và lần lượt có thể chỉ định tên máy chủ khác độc quyền của họ cho các tên miền phụ. Kỹ thuật này đã thực hiện các cơ chế phân phối DNS, chịu đựng lỗi, và giúp tránh sự cần thiết cho một trung tâm đơn lẻ để đăng ký được tư vấn và liên tục cập nhật.
#### 2.2 Nguyên Tắc Hoạt động
Mỗi nhà cung cấp dịch vụ vận hành và duy trì DNS server riêng của mình, gồm các máy bên trong phần riêng của mỗi nhà cung cấp dịch vụ đó trong Internet. Tức là, nếu một trình duyệt tìm kiếm địa chỉ của một website thì DNS server phân giải tên website này phải là DNS server của chính tổ chức quản lý website đó chứ không phải là của một tổ chức (nhà cung cấp dịch vụ) nào khác.

INTERNIC (Internet Network Information Center) chịu trách nhiệm theo dõi các tên miền và các DNS server tương ứng. INTERNIC là một tổ chức được thành lập bởi NSF (National Science Foundation), AT&T và Network Solution, chịu trách nhiệm đăng ký các tên miền của Internet. INTERNIC chỉ có nhiệm vụ quản lý tất cả các DNS server trên Internet chứ không có nhiệm vụ phân giải tên cho từng địa chỉ

DNS có khả năng truy vấn các DNS server khác để có được một cái tên đã được phân giải. DNS server của mỗi tên miền thường có hai việc khác biệt. Thứ nhất, chịu trách nhiệm phân giải tên từ các máy bên trong miền về các địa chỉ Internet, cả bên trong lẫn bên ngoài miền nó quản lý. Thứ hai, chúng trả lời các DNS server bên ngoài đang cố gắng phân giải những cái tên bên trong miền nó quản lý.

DNS server có khả năng ghi nhớ lại những tên vừa phân giải. Để dùng cho những yêu cầu phân giải lần sau. Số lượng những tên phân giải được lưu lại tùy thuộc vào quy mô của từng DNS.
#### 2.3 Các bước hoạt động
– Là một máy tính có nhiệm vụ là DNS Server, chạy dịch vụ DNS service.
– DNS Server là một cơ sở dữ liệu chứa các thông tin về vị trí của các DNS domain và phân giải các truy vấn xuất phát từ các Client.
– DNS Server có thể cung cấp các thông tin do Client yêu cầu, và chuyển đến một DNS Server khác để nhờ phân giải hộ trong trường hợp nó không thể trả lời được các truy vấn về những tên miền không thuộc quyền quản lý và cũng luôn sẵn sàng trả lời các máy chủ khác về các tên miền mà nó quản lý. DNS Server lưu thông tin của Zone, truy vấn và trả kết quả cho DNS Client.
– Máy chủ quản lý DNS cấp cao nhất là Root Server do tổ chức ICANN quản lý:

Là Server quản lý toàn bộ cấu trúc của hệ thống tên miền
Root Server không chứa dữ liệu thông tin về cấu trúc hệ thống DNS mà nó chỉ chuyển quyền (delegate) quản lý xuống cho các Server cấp thấp hơn và do đó Root Server có khả năng định đường đến của một domain tại bất kì đâu trên mạng

DNS có khả năng truy vấn các DNS server khác để có một cái tên đã được phân giải. DNS server của mỗi tên miền thường có 2 việc khác biệt. 
Thứ nhất chịu trách nhiệm phân giải tên từ các máy bên trong miền về các địa chỉ Internet, cả bên trong lẫn bên ngoài miền nó quản lý. 
Thứ hai, chúng trả lời các DNS server bên ngoài đang cố gắng phân giải những tên miền nó quản lý. DNS server có khả năng ghi nhớ lại những tên vừa phân giải. Để dùng cho những yêu cầu phân giải lần sau. Số lượng những tên phân giải được lưu lại tùy thuộc vào quy mô của từng DNS.

DNS server là một cơ sở dữ liệu chứa các thông tin về vị trị của các DNS domain và phân giải các truy vấn xuất phát từ client.

DNS server lưu thông tin của Zone, truy vấn và trả kết quả cho DNS client, chạy DNS service.

1. 
Truy vấn DNS bình thường.

-Quá trình máy tính cá nhân (gọi tắt là A) truy vấn tới địa chỉ www.vccloud.vn. Lúc này máy tính đang trỏ DNS tới DNS google 8.8.8.8 quá trình sẽ diễn ra như sau:
-Đầu tiên A gửi request hỏi DNS Server google hỏi thông tin về www.vccloud.vn, server DNS google sẽ gửi truy vấn đến server top level domain
-Top level domain lưu trữ thông tin về mọi tên miền trên mạng. Do đó nó sẽ gửi lại cho server DNS google địa chỉ IP của server quản lý tên miền vn (gọi tắt là server vn).
-Khi có địa chỉ IP của server vn thì lúc này server DNS google sẽ hỏi server vn về vccloud.vn server vn quản lý toàn bộ những trang web có domain vn, chúng sẽ gửi địa chỉ ip của server vccloud.vn cho server google.
-Sau đó server DNS google lại tiếp tục gửi truy vấn đến server vccloud.vn để hỏi thông tin về server quản lý dịch vụ www của vccloud.vn.
-Server vccloud.vn khi nhận được truy vấn sẽ gửi lại IP của server www.vccloud.vn cho server DNS google
-Và cuối cùng server DNS google sẽ gửi lại địa chỉ địa chỉ IP của server www.vccloud.vn cho A và bây giờ A có thể kết nối trực tiếp tới www.vccloud.vn.

2. Truy vấn DNS Forwarder 

– Một số DNS Server nội bộ không cho truy cập đến Internet vì mục đích bảo mật, nên DNS Server không thể truy vấn đến Root Server bằng Root Hint, vì thế ta phải sử dụng Forwarder, để chuyển các truy vấn của Client đến DNS Server được chỉ định.

#### 2.4 Mô hình lab
![](https://github.com/kidluc/NETWORKREPORT/blob/master/Screenshot%20from%202017-09-20%2011-12-37.png)
#### 2.5 Cấu hình các phần mềm DNS server.
Cấu hình DNS Server Bind9.

Tại Server:
Cài đặt bind9 và bind9utils:
```
apt install bind9 bind9utils bind9-docs
```

Cấu hình file **/etc/bind/named.conf.options**
Thêm IP trusted để truy vấn đến DNS Server
```
acl "trusted" {
        45.124.95.108;
};
```
Cấu hình tiếp phần options
```
options {
        directory "/var/cache/bind";

        dnssec-validation auto;

        auth-nxdomain no;    # conform to RFC1035
        listen-on-v6 { any; };

        recursion yes;                 # Cho phép truy vấn ngược
        allow-recursion { trusted; };  # Cho phép truy vấn từ trusted
        listen-on { 45.124.95.108; };   # Chỉ định IP DNS listen
        allow-transfer { none; };      # Tắt chức năng transfer

        forwarders {
                8.8.8.8;
                8.8.4.4;
        };
};
```

Cấu hình tiếp file **/etc/bind/named.conf.local**

Thêm zone có chứa Domain name để truy vấn.
```
zone "duylk.com" {	# Bind domain name duylk.com
        type master;
        file "/etc/bind/zones/db.duylk.com";	# Chỉ định database cho domain name ở trên
        allow-transfer { 45.124.95.108; };
};
```

Tạo một folder zone để chứa các database cho zone
```
mkdir /etc/bind/zones
```

Tiếp đó ta tạo một file database cho domain name ta đã khai báo ở trên

```
vim /etc/bind/zones/db.duylk.com
```

Bên trong file ta cấu hình như sau

```
;
; BIND data file for local loopback interface
;
$TTL    604800
@       IN      SOA     test.duylk.com. root.duylk.com. (
                              3         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
; name servers - NS records
     IN      NS      test.duylk.com.
; name servers - A records
test.duylk.com.          IN      A       45.124.95.108
```

Sau khi tạo xong ta restart lại bind9
```
service bind9 restart
```
Kiểm tra xem bind9 đã load các zones chưa, nếu load như hình dưới là các zones đã được load và DNS Server đã chay
![](https://github.com/kidluc/NETWORKREPORT/blob/master/Screenshot%20from%202017-09-20%2011-33-35.png)

Tại máy Client
Cấu hình file **/etc/resolv.conf**
Ta thêm 2 dòng vào file
```
nameserver 45.124.95.108
search  test.duylk.com
```
Sau đó ta có thể kiểm tra DNS qua lệnh nslookup hoặc lệnh dig
![](https://github.com/kidluc/NETWORKREPORT/blob/master/Screenshot%20from%202017-09-20%2011-39-18.png)
![](https://github.com/kidluc/NETWORKREPORT/blob/master/Screenshot%20from%202017-09-20%2011-39-11.png)


## 3. Giao thức ARP
#### 3.1 Lý Thuyết
Giao thức phân giải địa chỉ (Address Resolution Protocol hay ARP) là một giao thức truyền thông được sử dụng để chuyển địa chỉ từ tầng mạng (Internet layer) sang tầng liên kết dữ liệu theo mô hình OSI. Đây là một chức năng quan trọng trong giao thức IP của mạng máy tính.
ARP được sử dụng để từ một địa chỉ mạng (ví dụ một địa chỉ IPv4) tìm ra địa chỉ vật lý như một địa chỉ Ethernet (địa chỉ MAC), hay còn có thể nói là phân giải địa chỉ IP sang địa chỉ máy
#### 3.2 Nguyên Tắc Hoạt động
Trong mạng Ethernet và WLAN các gói IP không được gởi trực tiếp. Một gói IP được bỏ vào một khung Ethernet, rồi mới được gởi đi. Khung này có một địa chỉ gởi và địa chỉ đích. Các địa chỉ này là địa chỉ MAC của một card mạng. Một card mạng sẽ nhận các khung ethernet mà có địa chỉ đích là địa chỉ MAC của mình. Card này sẽ không lưu ý tới các khung khác. Giao thức ARP được dùng để kết nối giữ địa chỉ MAC và địa chỉ IP. Để làm việc hiệu quả nó có giữ một bảng ARP lưu trữ.
#### 3.3 Các bước hoạt động
B1: Máy tính 1 sẽ gửi một gói ARP Request để tìm ra máy tính có IP được người dùng nhập vào. Gói tin này sẽ được gửi đến mọi địa chỉ MAC trong mạng.
B2: Máy tính 2 có địa chỉ IP như trong gói ARP Request đã được máy 1 broadcast sẽ trả lời máy một bằng ARP Reply để xác nhận địa chỉ IP cũng như cung cấp cho máy một địa chỉ MAC của mình.
B3: Máy 1 nhận về thông điệp ARP Reply với địa chỉ MAC của máy 2 và sẽ lưu thông tin đó vào ARP Table và bắt đầu việc truyền tin.

## 4. Giao thức GRE
#### 4.1 Lý Thuyết
GRE (Generic Routing Encapsulation) là một giao thức của CISCO cho phép việc để một gói IP vào bên trong 1 gói IP khác và tạo ra điểm kết nối ảo để tunneled giữa các mạng công cộng hay VPN.
Nó xây dựng những tunnel giữa các router, các máy với nhau và sử dụng IP public của chúng để gói gọn đường truyền cũng như định tuyến nó qua Internet.
GRE là công cụ tạo tunnel khá đơn giản nhưng hiệu quả. Nó có thể tạo tunnel cho bấy kì giao thức lớp 3 nào.
GRE cho phép những giao thức định tuyến hoạt động trên kênh truyền của mình.
GRE không có cơ chế bảo mật tốt. Trong khi đó, IPSec cung cấp sự tin cậy cao. Do đó nhà quản trị thường kết hợp GRE với IPSec để tăng tính bảo mật, đồng thời cũng hỗ trợ IPSec trong việc định tuyến và truyền những gói tin có địa chỉ IP Muliticast
#### 4.2 Nguyên Tắc Hoạt động
Mỗi khi hosts gửi một thông tin nào đó cho server, GRE sẽ đóng gói tin IP của máy hosts gửi đi vào trong một gói IP khác và sử dụng địa chỉ IP của tunnel như là nguồn gửi đi và đích đến.
#### 4.3 Các bước hoạt động
Khi có gói tin được gửi đi, GRE thêm vào tối thiểu 24 byte vào gói tin, trong đó bao gồm 20-byte IP header mới, 4 byte còn lại là GRE header. GRE có thể tùy chọn thêm vào 12 byte mở rộng để cung cấp tính năng tin cậy như: checksum, key chứng thực, sequence number. Sau đó, nó sẽ gửi gói tin đi qua tunnel thông qua Internet và Public IP đã được định tuyến.
#### 4.4 Mô hình lab

![](https://github.com/kidluc/NETWORKREPORT/blob/master/Screenshot%20from%202017-09-07%2010-58-08.png)
#### 4.5 Cấu hình các phần mềm.
Bản cấu hình này sử dụng trên Ubuntu 16.04.

Với các máy muốn sử dụng GRE, đâu tiên ta cần phải khởi động GRE bằng câu lệnh:      ```modprobe ip_gre```
Có thể kiểm tra bằng câu lệnh ```ip tunnel show```

Sau đó với từng máy ta cấu hình theo như form cấu hình sau:
```
sudo ip tunnel add {interfaces: VD: gre1} mode gre remote {IP remote} local {IP local} ttl 255
sudo ip link set  {interface đã được add ở trên} up
sudo ip addr add {IP public của tunnel} dev {interfaces ở trên}
```
Ở đây, 2 máy làm lab có IP lần lượt là.
Máy A: 45.124.95.108
Máy B: 192.168.61.67

Cấu hình tại máy A:
```
modprobe ip_gre
sudo ip tunnel add gre1 mode gre remote 192.168.61.67 local 45.124.95.108 ttl 255
sudo ip link set gre1 up
ip addr add 10.10.10.3/24 dev gre1
```

Cấu hình tại máy B:
```
modprobe ip_gre
sudo ip tunnel add gre1 mode gre remote 45.124.95.108 local 192.168.61.67 ttl 255
sudo ip link set gre1 up
ip addr add 10.10.10.2/24 dev gre1
```
Sau khi cấu hình xong ta có thể kiểm tra bằng cách sử dụng lệnh ping đến IP public mà ta đã khai báo ở trên
![](https://github.com/kidluc/NETWORKREPORT/blob/master/Screenshot%20from%202017-09-07%2010-46-00.png)


## 5. Giao thức VXLAN
#### 5.1 Lý Thuyết
VXLAN (Virtual Extension LAN ) cung cấp các dịch vụ kết nối các Ethernet end systems và cung cấp phương tiện mở rộng mạng LAN qua mạng L3. VXLAN ID (VXLAN Network Identifier hoặc VNI) là 1 chuỗi 24-bits so với 12 bits của của VLAN ID. Do đó cung cấp hơn 16 triệu ID duy nhất.

VXLAN Tunnel End Point (VTEP) dùng để kết nối switch (hiện tại là virtual switch) đến mạng IP. VTEP nằm trong hypervisor chứa VMs. Chức năng của VTEP là đóng gói VM traffic trong IP header để gửi qua mạng IP.
#### 5.2 Nguyên Tắc Hoạt động
#### 5.3 Các bước hoạt động
#### 5.4 Mô hình lab
#### 5.5 Cấu hình các phần mềm.

## 6. Giao thức ICMP
####  6.1 Lý Thuyết
Internet Control Message Protocol (viết tắt là ICMP), là một giao thức của gói Internet Protocol. Giao thức này được các thiết bị mạng như router dùng để trao đổi các thông tin của dòng dữ liệu, thông báo lỗi và các thông tin trạng thái của TCP/IP. ICMP cũng có thể được sử dụng để chuyển tiếp các thông điệp truy vấn.
VD: lệnh * ping* hay * traceroute*,..
#### 6.2 Nguyên Tắc Hoạt động
ICMP sử dụng IP để làm cơ sở thông tin liên lạc bằng cách giải thích chính nó như là một lớp giao thức cao hơn, d. h. thông điệp ICMP được đóng gói trong các gói tin IP.
ICMP nhận ra một số tình trạng lỗi, nhưng không làm IP trở thành một giao thức đáng tin cậy.
ICMP phân tích sai sót trong mỗi gói IP, trừ các đối tượng mà mang một thông điệp ICMP.
Thông điệp ICMP không được gửi để trả lời các gói tin gởi tới các điểm đến mà có các địa chỉ multicast hoặc broadcast.
Thông điệp ICMP chỉ trả lời một địa chỉ IP được định danh rõ ràng.
#### 6.3 Các bước hoạt động
Máy A muốn kiếm tra kết nối đến máy B hay server thì máy A sẽ gửi đi một ICMP Echo Request đến địa chỉ của máy B hoặc server, router có nhiệm vụ chuyển dòng dữ liệu.
Nếu máy đích nhận được gói ICMP Echo Request, máy đích sẽ gửi về một gói ICMP Echo Reply. Nếu không có gói ICMP Echo Reply gửi về. ICMP sẽ đưa ra một thông điệp báo lỗi về máy A.
