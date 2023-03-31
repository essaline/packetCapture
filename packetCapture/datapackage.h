#ifndef DATAPACKAGE_H
#define DATAPACKAGE_H

#include <QString>
#include "format.h"

class DataPackage
{
public:
    DataPackage();
    static QString byteToString(const u_char* str,int size);
    u_char *pkt_content;

    void setDataLength(u_int length);
    void setTimestamp(QString timestamp);
    void setPacketType(int packetType);
    void setInfo(QString info);
    void setPacketPointer(const u_char* pkt_content,int size);

    QString getDataLength();
    QString getTimestamp();
    QString getPacketType();
    int getIntPackageType();
    QString getInfo();
    //get ip address
    QString getSource();
    QString getDestination();

    void setIPHeadLength(const int &ip_head_length);
    int getIPHeadLength();

    //mac info
    QString getSrcMACAddr();
    QString getDstMACAddr();
    QString getMACType();

    //ip info
    QString getStringIPHeadLength();
    QString getIPVersion();
    QString getIPTos();
    QString getIPTotalLength();
    QString getIPIdentification();
    QString getIPFlag();
    QString getIPDF();
    QString getIPMF();
    QString getIPFragmentOffset();
    QString getIPTTL();
    QString getIPProtocol();
    QString getIPChecksum();

    //icmp info
    QString getICMPType();
    QString getICMPCode();
    QString getICMPChecksum();
    QString getICMPIdentification();
    QString getICMPSequence();
    QString getICMPData(const int size);

    //arp info
    QString getARPType();
    QString getARPProtocolType();
    QString getARPHardwareLength();
    QString getARPProtocolLength();
    QString getARPOperationCode();
    QString getARPSrcEthAddr();
    QString getARPDstEthAddr();

    //tcp info
    QString getTCPSrcPort();
    QString getTCPDstPort();
    QString getTCPSequence();
    QString getTCPAcknowledgement();
    QString getTCPHeadLength();
    QString getTCPWindowSize();
    QString getTCPChecksum();
    QString getTCPUrgentPointer();
//    QString getTCP


    //udp info
    QString getUDPSrcPort();
    QString getUDPDstPort();
    QString getUDPChecksum();
    QString getUDPDataLength();

    //dns info
    QString getDNSTransactionId();
    QString getDNSFlags();
    QString getDNSQR();
    QString getDNSOpCode();
    QString getDNSAA();
    QString getDNSTC();
    QString getDNSRD();
    QString getDNSRA();
    QString getDNSRCode();
    QString getDNSQuestionNumber();
    QString getDNSAnswerNumber();
    QString getDNSAuthorityNumber();
    QString getDNSAdditionalNumber();
    QString getDNSDomainName();


private:
    //时间戳
    QString timestamp;
    u_int data_length;
    QString info;
    //数据包类型
    int packageType;

    int ip_head_length;
};

#endif // DATAPACKAGE_H
