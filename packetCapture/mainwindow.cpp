#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QString>
#include<QDebug>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    thread = new MultiThread;
    pointer = nullptr;
    count = 0;
    rowCount = -1;
    qdata.clear();
//    qdata = new QVector<DataPackage>;
    ui->setupUi(this);
    showNetworkCard();
    colors.push_back(QColor(QString("D6EFED").toUInt(nullptr,16)));
    colors.push_back(QColor(QString("B7D3DF").toUInt(nullptr,16)));
    colors.push_back(QColor(QString("CDF0EA").toUInt(nullptr,16)));
    colors.push_back(QColor(QString("F7DBF0").toUInt(nullptr,16)));
    colors.push_back(QColor(QString("FFD4B2").toUInt(nullptr,16)));

    ui->treeWidget->header()->hide();
    QStringList tableHeader;
    tableHeader<<"NO."<<"Time"<<"Source"<<"Destination"<<"Protocol"<<"Length"<<"Info";

    ui->tableWidget->setColumnCount(7);
    ui->tableWidget->setHorizontalHeaderLabels(tableHeader);
    ui->tableWidget->verticalHeader()->setVisible(false);
    ui->tableWidget->horizontalHeader()->setStretchLastSection(true);
    ui->tableWidget->setShowGrid(false);
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->tableWidget->setColumnWidth(0,100);
    ui->tableWidget->setColumnWidth(1,150);
    ui->tableWidget->setColumnWidth(2,240);
    ui->tableWidget->setColumnWidth(3,240);
    ui->tableWidget->setColumnWidth(4,150);
    ui->tableWidget->setColumnWidth(5,150);



    connect(ui->actionstart_2,&QAction::triggered,this,[=](){
        int res = capture();
        if(res&&pointer){
            ui->comboBox->setEnabled(false);
            thread->setPointer(pointer);
            thread->setFlag();
            thread->start();
        }
    });

    connect(ui->actionstop_2,&QAction::triggered,this,[=](){
        ui->comboBox->setEnabled(true);
        thread->resetFLag();
        thread->quit();
        thread->wait();
        if(pointer)
            pcap_close(pointer);
        pointer = nullptr;
    });

    connect(thread,&MultiThread::send,this,&MainWindow::handlePackage);



}

MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::showNetworkCard(){
    int n = pcap_findalldevs(&all_device,errBuffer);
    if(n==-1){
        ui->comboBox->addItem("error:"+QString(errBuffer));
    }else{
        ui->comboBox->clear();
        ui->comboBox->addItem("please choose networkCard!");

        for(device = all_device;device!=nullptr;device = device->next){
            ui->comboBox->addItem(device->description);
        }
    }
}

int MainWindow::capture(){
    if(device){
        //1000milliseconds：读取超时时间，1s ,65535：捕获包的最大程度，
        pointer = pcap_open_live(device->name,65535,1,1000,errBuffer);
    }else{
        return -1;
    }

    if(!pointer){
        pcap_freealldevs(all_device);
        device = nullptr;
        return -1;
    }else{
        statusBar()->showMessage("currentNetworkCrad:"+QString(device->description));
    }

    return 1;
}



void MainWindow::on_comboBox_currentIndexChanged(int index)
{
    int i =0;
    //这里的第一个是please choose networkCard ,不计入index的计算
    for(device = all_device;i<index-1;device = device->next,i++);
}


void MainWindow::handlePackage(DataPackage data){
    ui->tableWidget->insertRow(count);
    this->qdata.push_back(data);
    QString type = data.getPacketType();
    int int_type = data.getIntPackageType();

    ui->tableWidget->setItem(count,0,new QTableWidgetItem(QString::number(count+1)));
    ui->tableWidget->setItem(count,1,new QTableWidgetItem(data.getTimestamp()));
    ui->tableWidget->setItem(count,2,new QTableWidgetItem(data.getSource()));
    ui->tableWidget->setItem(count,3,new QTableWidgetItem(data.getDestination()));
    ui->tableWidget->setItem(count,4,new QTableWidgetItem(type));
    ui->tableWidget->setItem(count,5,new QTableWidgetItem(data.getDataLength()));
    ui->tableWidget->setItem(count,6,new QTableWidgetItem(data.getInfo()));
    for(int i =0;i<7;i++){
        ui->tableWidget->item(count,i)->setBackground(colors[int_type-1]);
    }
    count++;
}

void MainWindow::on_tableWidget_cellClicked(int row, int column)
{
    if(row ==rowCount ||row<0){
        return ;
    }

    ui->treeWidget->clear();
    rowCount = row;
    if(rowCount >qdata.size()){
        return ;
    }

    QString srcMac = qdata[row].getSrcMACAddr();
    QString dstMac = qdata[row].getDstMACAddr();
    QString macType = qdata[row].getMACType();
    QString macTopTree  = "Ethernet II, Src: "+srcMac +" , Dst: "+dstMac ;

    QTreeWidgetItem *macTopItem  = new QTreeWidgetItem(QStringList()<<macTopTree);
    ui->treeWidget->addTopLevelItem(macTopItem);
    macTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Destination: "+dstMac));
    macTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Source: "+srcMac));
    macTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Type: "+macType));

    QString packageType = qdata[row].getPacketType();
    if(packageType ==ARP){
        QString  arpOperationCode = qdata[row].getARPOperationCode();
        QTreeWidgetItem *arpTopItem = new QTreeWidgetItem(QStringList()<<"Address Resolution Protocol "+arpOperationCode);
        ui->treeWidget->addTopLevelItem(arpTopItem);
        arpTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Hardward type: " +qdata[row].getARPType()));
        arpTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Hardware size: "+qdata[row].getARPHardwareLength()));
        arpTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Protocol size: "+qdata[row].getARPProtocolLength()));
        arpTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Opcode: "+qdata[row].getARPOperationCode()));
        arpTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Send MAC address: "+qdata[row].getARPSrcEthAddr()));
        arpTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Send IP address: "+qdata[row].getSource()));
        arpTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Target MAC address: "+qdata[row].getARPDstEthAddr()));
        arpTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Target IP address: "+qdata[row].getDestination()));
        return ;
    }
    //ip数据包
    else{
        QString srcIp = qdata[row].getSource();
        QString dstIP = qdata[row].getDestination();
        QTreeWidgetItem *ipTopItem = new QTreeWidgetItem(QStringList()<<"Internet Protocol Version 4, Src: "+srcIp+", Dst: "+dstIP);
        ui->treeWidget->addTopLevelItem(ipTopItem);
        QString ipVersion = qdata[row].getIPVersion();
        ipTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Version:"+ipVersion));
        ipTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Header Length: "+QString::number(qdata[row].getIPHeadLength())));
        ipTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Type Of Service: "+qdata[row].getIPTos()));
        ipTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Total Length: "+qdata[row].getIPTotalLength()));
        ipTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Identification: "+qdata[row].getIPIdentification()));
        QTreeWidgetItem *flag = new QTreeWidgetItem(QStringList()<<"Flags: "+qdata[row].getIPFlag());
        ipTopItem->addChild(flag);
        flag->addChild(new QTreeWidgetItem(QStringList()<<"0... .....=Reserve Bit"));
        flag->addChild(new QTreeWidgetItem(QStringList()<<"Don't Fragment: "+qdata[row].getIPDF()));
        flag->addChild(new QTreeWidgetItem(QStringList()<<"More Fragments: "+qdata[row].getIPMF()));
        ipTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Fragment Offset: "+qdata[row].getIPFragmentOffset()));
        ipTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Time To Live: "+qdata[row].getIPTTL()));
        ipTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Protocol: "+qdata[row].getIPProtocol()));
        ipTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Header Checksum: "+qdata[row].getIPChecksum()));
        ipTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Source Address: "+srcIp));
        ipTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Destination Address: "+dstIP));

        if(packageType ==TCP){
            QString srcPort = qdata[row].getTCPSrcPort();
            QString dstPort = qdata[row].getTCPDstPort();
            QString seq = qdata[row].getTCPSequence();
            QString ack = qdata[row].getTCPAcknowledgement();
            QString len = qdata[row].getTCPHeadLength();
            QTreeWidgetItem *tcpTopItem = new QTreeWidgetItem(QStringList()<<"Transimission Control Protocol, Src Port: "+srcPort
                                                              +", Dst Port: "+dstPort
                                                              +", Seq: "+seq
                                                              +", Ack: "+ack
                                                              +", Len: "+len);
            ui->treeWidget->addTopLevelItem(tcpTopItem);
            tcpTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Source Port: "+srcPort));
            tcpTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Destination Port: "+dstPort));

            tcpTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Header Length: "+len));
            tcpTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number: "+seq));
            tcpTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Acknowledgment Number: "+ack));
            tcpTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Window Size: "+qdata[row].getTCPWindowSize()));
            tcpTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Checksum: "+qdata[row].getTCPChecksum()));
            tcpTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Urgent Pointer: "+qdata[row].getTCPUrgentPointer()));
            return ;
        }
        else if(packageType ==UDP||packageType ==DNS){
            QString srcPort = qdata[row].getUDPSrcPort();
            QString dstPort = qdata[row].getUDPDstPort();
            QString totalLength = qdata[row].getUDPDataLength();
            QString checksum = qdata[row].getUDPChecksum();
            QTreeWidgetItem *udpTopItem = new QTreeWidgetItem(QStringList()<<"User Datagram Protocol, Src Port: "+srcPort
                                                              +", Dst Port: "+dstPort);
            ui->treeWidget->addTopLevelItem(udpTopItem);
            udpTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Source Port: "+srcPort));
            udpTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Destination Port: "+dstPort));
            udpTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Length: "+totalLength));
            udpTopItem->addChild(new QTreeWidgetItem(QStringList()<<"checksum: "+checksum));
            int udpLength = totalLength.toUtf8().toInt();
            if(udpLength>0){
                udpTopItem->addChild(new QTreeWidgetItem(QStringList()<<"UDP Payload ("+QString::number(udpLength-8)+"bytes)"));
            }
            if(packageType ==DNS){
                QString transactionId = "0x"+qdata[row].getDNSTransactionId();
                QTreeWidgetItem *dnsTopItem;
                if(qdata[row].getDNSQR() =="1")
                    dnsTopItem= new QTreeWidgetItem(QStringList()<<"Domain Name System (response)");
                else
                    dnsTopItem= new QTreeWidgetItem(QStringList()<<"Domain Name System (request)");
                ui->treeWidget->addTopLevelItem(dnsTopItem);
                dnsTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Transaction ID: "<<transactionId));
                dnsTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Questions: "+qdata[row].getDNSAnswerNumber()));
                dnsTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Answer RRs: "+qdata[row].getDNSAnswerNumber()));
                dnsTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Authority RRs: "+qdata[row].getDNSAuthorityNumber()));
                dnsTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Addtional RRs: "+qdata[row].getDNSAdditionalNumber()));
                dnsTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Queries"));
                return ;
            }

            return ;
        }
        else if(packageType ==ICMP){
            int icmpLength = qdata[row].getIPTotalLength().toUtf8().toInt()-20;
            qDebug()<<icmpLength;
            if(icmpLength>0){
                //content length ,header length equal 8
                icmpLength -=8;
                QTreeWidgetItem *icmpTopItem = new QTreeWidgetItem(QStringList()<<"Internet Control Message Protocol");
                ui->treeWidget->addTopLevelItem(icmpTopItem);
                icmpTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Type: "+qdata[row].getICMPType()+" "+qdata[row].getInfo()));
                icmpTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Code: "+qdata[row].getICMPCode()));
                icmpTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Checksum: "+qdata[row].getICMPChecksum()));
                icmpTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Identifer: "+qdata[row].getICMPIdentification()));
                icmpTopItem->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number: "+qdata[row].getICMPSequence()));
                QTreeWidgetItem *data = new QTreeWidgetItem(QStringList()<<"Data ("+QString::number(icmpLength)+"bytes)");
                icmpTopItem->addChild(data);
                data->addChild(new QTreeWidgetItem(QStringList()<<"Data: "+qdata[row].getICMPData(icmpLength)));
                data->addChild(new QTreeWidgetItem(QStringList()<<"[Length: "+QString::number(icmpLength)+"]"));
                return;

            }
        }

    }
    return ;
}


