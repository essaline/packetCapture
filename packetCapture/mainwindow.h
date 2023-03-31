#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include<QVector>
#include<QList>

#include "pcap.h"
#include "multithread.h"
QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    void showNetworkCard();
    int capture();

private slots:
    void on_comboBox_currentIndexChanged(int index);

    void on_tableWidget_cellClicked(int row, int column);

public slots:
    void handlePackage(DataPackage data);

private:
    Ui::MainWindow *ui;
    pcap_if_t *all_device;
    pcap_if_t *device;
    //指向当前打开的实例
    pcap_t *pointer;
    char errBuffer[PCAP_ERRBUF_SIZE]; //256

    MultiThread *thread;
    long count;
    long rowCount ;
//    QVector<DataPackage> qdata;
    QList<DataPackage> qdata;
    QVector<QColor> colors;

};
#endif // MAINWINDOW_H
