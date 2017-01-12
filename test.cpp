#include <QtCore/QCoreApplication>
#include <QDebug>
#include "NetworkTime.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    qDebug() << NetworkTime::current();

    return a.exec();
}
