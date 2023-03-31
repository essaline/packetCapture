#ifndef FORMAT_H
#define FORMAT_H


typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;

#define ARP "ARP"
#define IP "IP"
#define ICMP "ICMP"
#define TCP "TCP"
#define UDP "UDP"
#define DNS "DNS"

/*
 MAC
 ---------------------------------------------------------
      6byte             |     6byte              |  2byte|
----------------------------------------------------------
   destination address  |   resource address     |  type  |
----------------------------------------------------------
*/
typedef struct{
    unsigned char eth_dst_address[6];
    unsigned char eth_src_address[6];
    u_short type;
}MAC_header;


/*
 * ip
-----------------------------------------------
 4bit    |  4bit       | 1byte|   2byte
 -----------------------------------------------
 version | head length | tos  | total length   |
 -----------------------------------------------
 identification(16bit) |(R|D|M)(3bit)|offset (13bit)|
 ------------------------------------------------
  8bit     |    8bit        |16bit               |
-------------------------------------------------
 ttl      |  protocol        |  checksum         |
--------------------------------------------------
               source ip address                 |
-------------------------------------------------
              destination ip address            |
--------------------------------------------------
*/

typedef struct{
    //这里head_length必须放在第一个，我也不知道为啥。或者可以把version ,head_length用一个字节表示，
    //那head_length在低位，version在高位，计算version :((IP_header->vserion>>4)0x0F)
    u_char head_length:4;
    u_char version:4;
    u_char tos;
    u_short total_length;
    u_short identification;
    u_short RDM:3; //1：未使用，2：0：允许分片，1：不允许分片，3:0：没有更多分片，1：有更多分片
    u_short offset:13;
    u_char ttl;
    u_char protocol;
    u_short checksum;
    u_int src_IP_address;
    u_int dst_IP_address;
}IP_header;





/*
 * tcp
---------------------------------------------
            16bit     |         2byte        |
----------------------------------------------
     source port      |      destination port  |
-----------------------------------------------
    sequence number
----------------------------------------------
        ack number
----------------------------------------------
  headlength(4) |reverse(6) | URG|ACK|PSH|RST|SYN|FIN|    window size(2byte)|
--------------------------------------------------------------
 checksum(2byte)       |   urgent pointer |
 -----------------------------------------
 */
typedef struct{
    u_short source_port;
    u_short destination_port;
    u_int sequence_number;
    u_int ack_number;
    u_short head_length:4;
    u_short reverse:6;
    u_short URG:1;
    u_short ACK:1;
    u_short PSH:1;
    u_short RST:1;
    u_short SYN:1;
    u_short FIN:1;
    u_short window_size;
    u_short checksum;
    u_short urgent_pointer;
}TCP_header;


/*
 * udp
------------------------------------
 source port(2byte)  | destination port(2byte)
 ------------------------------------------
 total length(2byte)  | checksum(2byte)
 ----------------------------------------
 */

typedef struct{
    u_short source_port;
    u_short destination_port;
    u_short total_length;
    u_short checksum;
}UDP_header;

/*
 * arp
----------------------------------
type(2byte)  | protocol(2byte)  | mac_addr_length(1byte) |ip_addr_length(1byte) |
---------------------------------------------------------------------------------
operate_type(2byte) |source_mac_address (6byte) |source_ip_address(4byte) | destination_mac_addr(6byte) |dst_ip_addr(4byte)
---------------------------------------------------------
*/

typedef struct{
    u_short type;
    u_short protocol;
    u_char MAC_addr_length;//eth:6
    u_char IP_addr_length;//ipv4:4
    u_short operate_code;  //arp request:1, arp response:2,rarp request:3,rarp response:4
    u_char src_MAC_addr[6];
//    u_char src_IP_addr[4];
    u_int src_IP_addr;
    u_char dst_MAC_addr[6];
//    u_char dst_IP_addr[4];
    u_int dst_IP_addr;
}ARP_header;


/*
 * icmp
-----------------------------------
type (1byte) | code(1byte) |checksum(2byte)
------------------------------------------
identification (2byte) | sequence (2byte)
----------------------------------------
*/

typedef struct{
    u_char type;
    u_char code;
    u_short checksum;
    u_short identification;
    u_short sequence;
}ICMP_header;


/*
 * dns
------------------------------------------------
identification(2byte) | QR(1bit)(0:请求，1：应答)| opCode(4bit)(值0是标准查询，1是反向查询，2死服务器状态查询) |
------------------------------------------------------------------------------------------------
AA(1bit)(授权应答(Authoritative Answer) - 这个比特位在应答的时候才有意义，指出给出应答的服务器是查询域名的授权解析服务器) |
----------------------------
TC(1bit)    (截断(TrunCation) - 用来指出报文比允许的长度还要长，导致被截断)
-----------------------
RD(1bit)  ( recursion desired,这个比特位被请求设置，应答的时候使用的相同的值返回。如果设置了RD，就建议域名服务器进行递归解析，递归查询的支持是可选的)
------------------------------------------------------
RA(1bit) (recursion available这个比特位在应答中设置或取消，用来代表服务器是否支持递归查询)
---------------------------------
Z(3bit) (保留值，值为0.)
-------------------------------
RCode(4bit) (应答码，类似http的stateCode一样，值0没有错误、1格式错误、2服务器错误、3名字错误、4服务器不支持、5拒绝。)
---------------------------------------
questions(16bit) |answer RRs(2byte)
--------------------------------------------
authority RRs (2byte) | adtional RRs (2byte)
--------------------------------------------
*/

typedef struct {
    u_short identification;
    u_short QR:1;
    u_short opCode:4;
    u_short AA:1;
    u_short TC:1;
    u_short RD:1;
    u_short RA:1;
    u_short zero:3;
    u_short RCode:4;
    u_short questions;
    u_short answers;
    u_short authority;
    u_short addtional;
}DNS_header;




#endif // FORMAT_H

