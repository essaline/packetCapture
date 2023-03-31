#include "multithread.h"
#include <time.h>
#include<QDebug>

MultiThread::MultiThread()
{
    this->isDone = true;
    this->pointer = nullptr;
    this->pkt_header  = nullptr;
    this->pkt_data = nullptr;
    this->ip_head_length = 0;
}

bool MultiThread::setPointer(pcap_t* pointer){
    this->pointer = pointer;
    if(pointer)
        return true;
    else
        return false;
}

void MultiThread::setFlag(){
    this->isDone = false;
}

void MultiThread::resetFLag(){
    this->isDone = true;
}

void MultiThread::run(){
    u_short number_package = 0;
    while(!isDone){

        int res = pcap_next_ex(pointer,&pkt_header,&pkt_data);
        if(res == 0)
           continue;
        local_time_sec = pkt_header->ts.tv_sec;
        localtime_s(&local_time,&local_time_sec);
        strftime(timeString,sizeof(timeString),"%H:%M:%S",&local_time);
        QString info = "";
        int type =  ethernetPackegeHandle(pkt_data,info);
        if(type){
            DataPackage data ;
            int len = pkt_header->len;
            data.setPacketType(type);
            data.setInfo(info);
            data.setDataLength(len);
            data.setIPHeadLength(this->ip_head_length);
            data.setTimestamp(timeString);
            data.setPacketPointer(pkt_data,len);
            if(data.pkt_content!=nullptr){
                emit send(data);
                number_package ++;
            }else
                continue;

        }else
            continue;
    }
    return ;
}


int MultiThread::ethernetPackegeHandle(const u_char *pkt_content,QString &info){
    MAC_header * mac_package;
    u_short content_type;
    mac_package = (MAC_header*)pkt_content;
    //ntohs:将一个16位数的网络字节顺序转化为主机字节顺序  即：network to host
    //htons :相反 ，即：host to network
    content_type = ntohs(mac_package->type);
    switch(content_type){
            //ip数据报
        case 0x0800 :{
             int ipPackageLength =0 ;
             int res  =ipPackageHandle(pkt_content,ipPackageLength,this->ip_head_length);
             switch(res){
             case 1:{
                 info = icmpPackageHandle(pkt_content,this->ip_head_length);
                 return 2;
             }
             case 6:{
                 return tcpPackageHandle(pkt_content,info,ipPackageLength,this->ip_head_length);
             }
             case 17:{
                 return udpPackageHandle(pkt_content,info,ipPackageLength,this->ip_head_length);
             }
             default: break;
             }
             break;
        }
        //arp数据报
        case 0x0806:{
            info = arpPackageHandle(pkt_content);
            return 1;
        }
        default:break;
    }

    return 0;

}

QString MultiThread::arpPackageHandle(const u_char *pkt_content){
    ARP_header *arp = (ARP_header*)(pkt_content +14);
    u_short op_code = ntohs(arp->operate_code);
    QString result = "";

    sockaddr_in *addr = nullptr;
    addr->sin_addr.S_un.S_addr= arp->src_IP_addr;
    QString srcIP = QString(inet_ntoa(addr->sin_addr));

    u_char *src_MAC_addr = arp->src_MAC_addr;
    QString srcMAC =  DataPackage::byteToString(src_MAC_addr,1)+":"
            +DataPackage::byteToString(src_MAC_addr+1,1)+":"
            +DataPackage::byteToString(src_MAC_addr+2,1)+":"
            +DataPackage::byteToString(src_MAC_addr+3,1)+":"
            +DataPackage::byteToString(src_MAC_addr+4,1)+":"
            +DataPackage::byteToString(src_MAC_addr+5,1);

    addr->sin_addr.S_un.S_addr = arp->dst_IP_addr;
    QString dstIP = QString(inet_ntoa(addr->sin_addr));

    switch(op_code){
    case 1: result = "Who has "+dstIP +" Tell "+srcIP;
        break;
    case 2:result = srcIP +" at "+srcMAC ;
        break;
    default:
        break;
    }

    return result;
}

int MultiThread::ipPackageHandle(const u_char *pkt_content,int &ipPackageLength,int &ipHeadLength){
    IP_header *ip_package;
    //14是mac层头部的长度
    ip_package = (IP_header*)(pkt_content+14);
    //icmp:1,tcp:6,udp:17,igmp:88
    int protocol = ip_package->protocol;
    ipPackageLength = ntohs(ip_package->total_length)-ip_package->head_length*4;
    this->ip_head_length = ip_package->head_length*4;
    ipHeadLength = ip_package->head_length*4;
    return protocol;

}

QString MultiThread::icmpPackageHandle(const u_char *pkt_content,const int &ipHeadLength){
    ICMP_header *icmp = (ICMP_header*)(pkt_content+14+ipHeadLength);
    u_char type = icmp->type;
    u_char code = icmp->code;
    QString result = "";
    switch(type){
    case 0:if(!code)
                result ="Echo reply(ping)";
            break;
    case 3:switch(code){
        case 0:result = "Network unreachable";
            break;
        case 1:result = "Host unreachable";
            break;
        case 2:result ="Protocol unreachable";
            break;
        case 3:result ="Port unreachable";
            break;
        case 4: result = "Fragmentation needed but no frag. bit set";
            break;
        case 5: result ="Source routing failed";
            break;
        case 6: result = "Destination network unknow";
            break;
        case 7:result = "Destination host unknow";
            break;
        default :break;
        }
    case 5:if(code==1)
                result ="Redirct for host";
            break;
    case 8:if(code == 0)
                result = "Echo request(ping)";
            break;
    case 11:if(code == 0)
                result ="TTL equal 0 during transit";
            break;
    case 12:if(code ==0 )
                result  ="IP head bad";
            break;
     default :break;
    }
    return result;

}


int MultiThread::tcpPackageHandle(const u_char *pkt_content,QString &info,int &ipPackageLength,int &ipHeadLength){
    TCP_header *tcp;
    tcp = (TCP_header*)(pkt_content+14+ipHeadLength);
    u_short src =ntohs( tcp->source_port);
    u_short dst =ntohs( tcp->destination_port);
    QString proSnd = "";
    QString proRcv = "";

    int type =3;
    int tcpData = ipPackageLength - tcp->head_length*4;

    if(src ==443 ||dst ==443){
        if(src ==443)
            proSnd ="(https)";
        else
            proRcv = "(https)";
    }
    info +=QString::number(src)+proSnd +" -> "+QString::number(dst)+proRcv;
    QString flag = "";
    if(tcp->PSH)
        flag = "PSH,";
    if(tcp->URG)
        flag  ="URG,";
    if(tcp->RST)
        flag = "RST,";
    if(tcp->ACK)
        flag = "ACK,";
    if(tcp->SYN)
        flag = "SYN,";
    if(tcp->FIN)
        flag = "FIN,";

     if(flag!=""){
        flag = flag.left(flag.length()-1);
        info += " ["+flag+"] ";
     }
    u_int sequence =ntohl(tcp->sequence_number);
    u_int ack = ntohl(tcp->ack_number);
    u_short window = ntohs(tcp->window_size);
    info +=" Seq:"+QString::number(sequence)+" ACK:"+QString::number(ack)+" window_size:"+QString::number(window) +" Len:"+QString::number(tcpData);
    return type;
}

int MultiThread::udpPackageHandle(const u_char *pkt_content,QString &info,const int &ipPackageLength,const int &ipHeadLength){
    UDP_header *udp = (UDP_header*)(pkt_content +14 +ipHeadLength);
    u_short src_port = ntohs(udp->source_port);
    u_short dst_port = ntohs(udp->destination_port);

    if(dst_port == 53 ||src_port ==53){
        info = dnsPackageHandle(pkt_content,ipHeadLength);
        return 5;
    }
    QString result = QString::number(src_port) + " -> " +QString::number(dst_port);
    result +=" len: " +QString::number(ntohs(udp->total_length));
    info = result;
    return 4;
}


QString MultiThread::dnsPackageHandle(const u_char *pkt_conent,const int &ipHeadLength){
    DNS_header *dns = (DNS_header*)(pkt_conent +14+ipHeadLength + 8);
    u_short identification  = ntohs(dns->identification);
    u_short QR = ntohs(dns->QR);
    QString info = "";
    if(QR)
        info  = "Standard reply";
    else
        info = "Standard query";

    QString name ="";
    char *domain = (char*)(pkt_conent+14+ipHeadLength+8 + 12);
    while(*domain!=0){
        //域名最大长度为63个字符
        if(domain&&(*domain)<64){
            int len = *domain;
            domain++;
            for(int i = 0;i<len;i++){
                name +=(*domain);
                domain++;
            }
            name+='.';
        }else
            break;
    }
    name = name.left(name.length()-1);
    return info+"  0x" +QString::number(identification)+"  "+name;
}













