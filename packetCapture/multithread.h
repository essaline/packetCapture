#ifndef MULTITHREAD_H
#define MULTITHREAD_H
#include<QThread>
#include "pcap.h"
#include "format.h"
#include "datapackage.h"

class MultiThread :public QThread
{
    Q_OBJECT
public:
    MultiThread();
    void run() override;
    bool setPointer(pcap_t* pointer);
    void setFlag();
    void resetFLag();

    int ethernetPackegeHandle(const u_char *pkt_content,QString &info);
    int ipPackageHandle(const u_char* pkt_content,int &ipPackageLength,int &ipHeadLength);
    int tcpPackageHandle(const u_char *pkt_content,QString &info, int &ipPackageLength,int &ipHeadLength);
    QString icmpPackageHandle(const u_char* pkt_content,const int &ipHeadLength);
    int udpPackageHandle(const u_char *pkt_content,QString &info,const int &ipPackageLength,const int &ipHeadLength);
    QString arpPackageHandle(const u_char *pkt_content);
    QString dnsPackageHandle(const u_char *pke_conent,const int &ipHeadLength);


private:
    pcap_t *pointer;
    /**
     * Header of a packet in the dump file.
     *Each packet in the dump file is prepended with this generic header. This gets around the problem of different headers for different packet interfaces.
    */
    struct pcap_pkthdr *pkt_header;
    const u_char *pkt_data;
    time_t local_time_sec;
    struct tm local_time;
    char timeString[16];
    bool isDone;
    int ip_head_length;


signals:
    void send(DataPackage data);
};

#endif // MULTITHREAD_H
