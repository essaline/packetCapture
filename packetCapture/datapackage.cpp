#include<QMetaType>
#include<winsock2.h>
#include "datapackage.h"
#include<QDebug>

DataPackage::DataPackage()
{
    qRegisterMetaType<DataPackage>("DataPackage");
    this->data_length = 0;
    this->timestamp = "";
    this->packageType = 0;
    this->ip_head_length = 0;


}

QString DataPackage::byteToString(const u_char* str,int size){
    QString result = "";
    for(int i =0;i<size;i++){
        char first = str[i]>>4;
        //即高位大于10
        if(first>0x0A){
            //ox41 :A 的ascall编码
            first  = first+0x41-0x0A;
        }else{
            //0x30 :数字0的ascall编码
            first += 0x30;
        }
        char second = str[i]&0x0F;
        if(second >0x0A){
            second = second +0x41-0x0A;
        }else{
            second += 0x30;
        }
        result.append(first);
        result.append(second);
    }
    return result;
}

void DataPackage::setInfo(QString info){
    this->info = info;
}

void DataPackage::setPacketPointer(const u_char * pkt_content,int size){
//    this->pkt_content = (u_char*)malloc(size);
    this->pkt_content = new u_char[size];
    memcpy(this->pkt_content,pkt_content,size);
//    this->pkt_content[size] = '\0';
}

void DataPackage::setTimestamp(QString timestamp){
    this->timestamp = timestamp;
}

void DataPackage::setDataLength(u_int data_length){
    this->data_length = data_length;
}

void DataPackage::setPacketType(int packetType){
    this->packageType = packetType;
}

QString DataPackage::getInfo(){
    return this->info;
}

QString DataPackage::getTimestamp(){
    return this->timestamp;
}

QString DataPackage::getDataLength(){
    return QString::number(this->data_length);
}

QString DataPackage::getPacketType(){
    switch(this->packageType){
    case 1: return ARP;
    case 2: return ICMP;
    case 3: return TCP;
    case 4: return UDP;
    case 5: return DNS;
    default:return "";
    }
}

int DataPackage::getIntPackageType(){
    return packageType;
}

void DataPackage::setIPHeadLength(const int &ip_head_length){
    this->ip_head_length = ip_head_length;
}

int DataPackage::getIPHeadLength(){
    return ip_head_length;
}


QString DataPackage::getSource(){
    //arp
    if(packageType ==1){
        ARP_header* arp = (ARP_header*)(this->pkt_content + 14);
        sockaddr_in src ;
        src.sin_addr.S_un.S_addr = arp->src_IP_addr;
        return QString(inet_ntoa(src.sin_addr));
    }
    //ip
    else{
        IP_header *ip = (IP_header*)(this->pkt_content+14);
        sockaddr_in src;
        src.sin_addr.S_un.S_addr = ip->src_IP_address;
        return QString(inet_ntoa(src.sin_addr));
    }
}

QString DataPackage::getDestination(){
    if(packageType == 1){
        ARP_header* arp = (ARP_header*)(this->pkt_content + 14);
        sockaddr_in dst ;
        dst.sin_addr.S_un.S_addr = arp->dst_IP_addr;
        return QString(inet_ntoa(dst.sin_addr));
    }else{
        IP_header *ip = (IP_header*)(this->pkt_content+14);
        sockaddr_in dst;
        dst.sin_addr.S_un.S_addr = ip->dst_IP_address;
        return QString(inet_ntoa(dst.sin_addr));
    }
}

QString DataPackage::getSrcMACAddr(){
    MAC_header * mac = (MAC_header*)pkt_content;
    QString result ="";
    u_char *addr ;
    if(mac){
       addr = mac->eth_src_address;
       if(addr){
           result+=byteToString(addr,1)+":"
                   +byteToString(addr+1,1)+":"
                   +byteToString(addr+2,1)+":"
                   +byteToString(addr+3,1)+":"
                   +byteToString(addr+4,1)+":"
                   +byteToString(addr+5,1);

           if(result == "FF:FF:FF:FF:FF:FF")
               return "FF:FF:FF:FF:FF:FF(Broadcast)";
           else
               return result;
       }
    }
    return result;
}

QString DataPackage::getDstMACAddr(){
    MAC_header * mac = (MAC_header*)pkt_content;
    QString result ="";
    u_char *addr ;
    if(mac){
       addr = mac->eth_dst_address;
       if(addr){
           result+=byteToString(addr,1)+":"
                   +byteToString(addr+1,1)+":"
                   +byteToString(addr+2,1)+":"
                   +byteToString(addr+3,1)+":"
                   +byteToString(addr+4,1)+":"
                   +byteToString(addr+5,1);

           if(result == "FF:FF:FF:FF:FF:FF")
               return "FF:FF:FF:FF:FF:FF(Broadcast)";
           else
               return result;
       }
    }
    return result;
}

QString DataPackage::getMACType(){
    MAC_header * mac = (MAC_header*)pkt_content;
    u_short type = ntohs( mac->type);
    switch (type) {
        case 0x0800: return "IPv4(0x800)";
        case 0x0806:return "ARP(0x0806)";
        default:{
            return "";
        }
        }
}

//ip function
QString DataPackage::getIPVersion(){
    IP_header *ip = (IP_header*)(pkt_content+14);
    return QString::number(ip->version);
}

QString DataPackage::getIPProtocol(){
    IP_header *ip = (IP_header*)(pkt_content+14);
    u_char protocol = ip->protocol;
    switch(protocol){
        case 1:return "ICMP (1)";
    case 6:return "TCP (6)";
    case 17: return "UDP (17)";
    default:return QString::number(ip->protocol);
    }
}

QString DataPackage::getIPTos(){
    IP_header *ip = (IP_header*)(pkt_content+14);
    return QString::number(ip->tos);
}

QString DataPackage::getIPTotalLength(){
    IP_header *ip = (IP_header*)(pkt_content+14);
    return QString::number(ntohs(ip->total_length*4));
}

QString DataPackage::getIPChecksum(){
    IP_header *ip = (IP_header*)(pkt_content+14);
    return QString::number(ntohs(ip->checksum),16);
}

QString DataPackage::getIPIdentification(){
    IP_header *ip = (IP_header*)(pkt_content+14);
    return QString::number(ntohs(ip->identification));
}

QString DataPackage::getIPFragmentOffset(){
    IP_header *ip = (IP_header*)(pkt_content+14);
    return QString::number(ntohs(ip->offset)&0x1FFF);
}

QString DataPackage::getIPDF(){
    IP_header *ip = (IP_header*)(pkt_content+14);
    return QString::number(((ip->RDM&0x02)>>1));
}

QString DataPackage::getIPMF(){
    IP_header *ip = (IP_header*)(pkt_content+14);
    return QString::number((ip->RDM&0x01));
}

QString DataPackage::getIPTTL(){
    IP_header *ip = (IP_header*)(pkt_content+14);
    return QString::number(ip->ttl);
}

QString DataPackage::getIPFlag(){
    IP_header *ip = (IP_header*)(pkt_content+14);
    return QString::number(ntohs(ip->RDM));
}


//icmp function
QString DataPackage::getICMPType(){
    ICMP_header *icmp = (ICMP_header*)(pkt_content+14+ip_head_length);
    return QString::number(icmp->type);
}

QString DataPackage::getICMPCode(){
    ICMP_header *icmp = (ICMP_header*)(pkt_content+14+ip_head_length);
    return QString::number(icmp->code);
}

QString DataPackage::getICMPChecksum(){
    ICMP_header *icmp = (ICMP_header*)(pkt_content+14+ip_head_length);
    return QString::number(ntohs(icmp->checksum));
}

QString DataPackage::getICMPIdentification(){
    ICMP_header *icmp = (ICMP_header*)(pkt_content+14+ip_head_length);
    return QString::number(ntohs(icmp->identification));
}

QString DataPackage::getICMPSequence(){
    ICMP_header *icmp = (ICMP_header*)(pkt_content+14+ip_head_length);
    return QString::number(ntohs(icmp->sequence));
}

QString DataPackage::getICMPData(const int size){
    u_char *icmp = (u_char*)(pkt_content+14+ip_head_length + 8);
    QString result = "";
    result+=byteToString(icmp,size);
    return result;
}

//arp function
QString DataPackage::getARPType(){
    ARP_header *arp  =(ARP_header*)(pkt_content+14);
    QString result = "";
    if(ntohs(arp->type) ==1)
        result = "Ethernet(1)";
    else
        result = QString::number(ntohs(arp->type));
    return result;
}

QString DataPackage::getARPProtocolType(){
    ARP_header *arp  =(ARP_header*)(pkt_content+14);
    QString result ="";
    if(ntohs(arp->protocol)==0x0800){
        result = "IPv4 (0x0800)";
    }else
       result = QString::number(ntohs(arp->protocol));
    return result;
}

QString DataPackage::getARPHardwareLength(){
    ARP_header *arp  =(ARP_header*)(pkt_content+14);
    return QString::number(arp->MAC_addr_length);
}

QString DataPackage::getARPProtocolLength(){
    ARP_header *arp  =(ARP_header*)(pkt_content+14);
    return QString::number(arp->IP_addr_length);
}

QString DataPackage::getARPOperationCode(){
    ARP_header *arp  =(ARP_header*)(pkt_content+14);
    u_short code = ntohs(arp->operate_code);
    if(code ==1||code ==3)
        return "request("+QString::number(code)+")";
    else if(code ==2 ||code == 4)
        return "reply("+QString::number(code)+")";
    return "";
}

QString DataPackage::getARPSrcEthAddr(){
    ARP_header *arp  =(ARP_header*)(pkt_content+14);
    u_char*addr;
    QString result ="";
    addr = arp->src_MAC_addr;
    if(addr){
               result = byteToString(addr,1) + ":"
                        + byteToString((addr+1),1) + ":"
                        + byteToString((addr+2),1) + ":"
                        + byteToString((addr+3),1) + ":"
                        + byteToString((addr+4),1) + ":"
                        + byteToString((addr+5),1);
                return result;
            }
    return result;
}

QString DataPackage::getARPDstEthAddr(){
    ARP_header *arp  =(ARP_header*)(pkt_content+14);
    u_char*addr;
    QString result ="";
    addr = arp->dst_MAC_addr;
    if(addr){
               result = byteToString(addr,1) + ":"
                        + byteToString((addr+1),1) + ":"
                        + byteToString((addr+2),1) + ":"
                        + byteToString((addr+3),1) + ":"
                        + byteToString((addr+4),1) + ":"
                        + byteToString((addr+5),1);
                return result;
            }
    return result;
}


//tcp function
QString DataPackage::getTCPSrcPort(){
    TCP_header *tcp = (TCP_header*)(pkt_content + 14+ip_head_length);
    return QString::number(ntohs(tcp->source_port));
}

QString DataPackage::getTCPDstPort(){
    TCP_header *tcp = (TCP_header*)(pkt_content + 14+ip_head_length);
    return QString::number(ntohs(tcp->destination_port));
}

QString DataPackage::getTCPSequence(){
    TCP_header *tcp = (TCP_header*)(pkt_content + 14+ip_head_length);
    return QString::number(ntohl(tcp->sequence_number));
}

QString DataPackage::getTCPAcknowledgement(){
    TCP_header *tcp = (TCP_header*)(pkt_content + 14+ip_head_length);
    return QString::number(ntohl(tcp->ack_number));
}

QString DataPackage::getTCPHeadLength(){
    TCP_header *tcp = (TCP_header*)(pkt_content + 14+ip_head_length);
    return QString::number(ntohs(tcp->head_length));
}

QString DataPackage::getTCPWindowSize(){
    TCP_header *tcp = (TCP_header*)(pkt_content + 14+ip_head_length);
    return QString::number(ntohs(tcp->window_size));
}

QString DataPackage::getTCPChecksum(){
    TCP_header *tcp = (TCP_header*)(pkt_content + 14+ip_head_length);
    return QString::number(ntohs(tcp->checksum));
}

QString DataPackage::getTCPUrgentPointer(){
    TCP_header *tcp = (TCP_header*)(pkt_content + 14+ip_head_length);
    return QString::number(ntohs(tcp->urgent_pointer));
}

//udp function
QString DataPackage::getUDPSrcPort(){
    UDP_header *udp = (UDP_header*)(pkt_content +14 +ip_head_length);
    return QString::number(ntohs(udp->source_port));
}

QString DataPackage::getUDPDstPort(){
    UDP_header *udp = (UDP_header*)(pkt_content +14 +ip_head_length);
    return QString::number(ntohs(udp->destination_port));
}

QString DataPackage::getUDPDataLength(){
    UDP_header *udp = (UDP_header*)(pkt_content +14 +ip_head_length);
    return QString::number(ntohs(udp->total_length));
}

QString DataPackage::getUDPChecksum(){
    UDP_header *udp = (UDP_header*)(pkt_content +14 +ip_head_length);
    return QString::number(ntohs(udp->checksum));
}

//dns function
QString DataPackage::getDNSTransactionId(){
    DNS_header *dns = (DNS_header*)(pkt_content +14 +ip_head_length + 8);
    return QString::number(ntohs(dns->identification),16);
}

QString DataPackage::getDNSQR(){
    DNS_header *dns = (DNS_header*)(pkt_content +14 +ip_head_length + 8);
    return QString::number(ntohs(dns->QR));
}

QString DataPackage::getDNSOpCode(){
    DNS_header *dns = (DNS_header*)(pkt_content +14 +ip_head_length + 8);
    return  QString::number(ntohs(dns->opCode));
}


QString DataPackage::getDNSQuestionNumber(){
    DNS_header *dns = (DNS_header*)(pkt_content +14 +ip_head_length + 8);
    return QString::number(ntohs(dns->questions));
}

QString DataPackage::getDNSAnswerNumber(){
    DNS_header *dns = (DNS_header*)(pkt_content +14 +ip_head_length + 8);
    return QString::number(ntohs(dns->answers));
}

QString DataPackage::getDNSAuthorityNumber(){
    DNS_header *dns = (DNS_header*)(pkt_content +14 +ip_head_length + 8);
    return QString::number(ntohs(dns->authority));
}

QString DataPackage::getDNSAdditionalNumber(){
    DNS_header *dns = (DNS_header*)(pkt_content +14 +ip_head_length + 8);
    return QString::number(ntohs(dns->addtional));
}

QString DataPackage::getDNSDomainName(){
    char *dns = (char*)(pkt_content +14 +ip_head_length + 8 +12);

}
