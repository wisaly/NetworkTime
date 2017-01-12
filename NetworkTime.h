/* This file is part of Network Time, a library get time from ntp server easily.
 *
 * Copyright (C) 2017 Chris <wisaly@gmail.com>
 * 
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with QNtp. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NETWORK_TIME_H
#define NETWORK_TIME_H
#include <QtGlobal>
#include <QSharedDataPointer>
#include <QDateTime>
#include <QSharedData>
#include <QtEndian>
#include <QUdpSocket>
#include <QHostAddress>

namespace qntp{
    /* Code in namespace qntp is modified from QNtp, a library that implements NTP protocol.
     * Origin repo: <https://code.google.com/p/qntp/>
     * Copyright (C) 2011 Alexander Fokin <apfokin@gmail.com>
     *
     * QNtp is free software; you can redistribute it and/or
     * modify it under the terms of the GNU Lesser General Public
     * License as published by the Free Software Foundation; either
     * version 3 of the License, or (at your option) any later version.
     *
     * QNtp is distributed in the hope that it will be useful, but WITHOUT ANY
     * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
     * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
     * for more details.
     *
     * You should have received a copy of the GNU Lesser General Public
     * License along with QNtp. If not, see <http://www.gnu.org/licenses/>. */

    enum NtpMode {
        ReservedMode = 0,         /**< Reserved. */
        SymmetricActiveMode = 1,  /**< Symmetric active. */
        SymmetricPassiveMode = 2, /**< Symmetric passive. */
        ClientMode = 3,           /**< Client. */
        ServerMode = 4,           /**< Server. */
        BroadcastMode = 5,        /**< Broadcast. */
        ControlMode = 6,          /**< NTP control message. */
        PrivateMode = 7,          /**< Reserved for private use. */
    };
    namespace detail {
        namespace {
            const qint64 january_1_1900 = -2208988800000ll;
        }
    }

#pragma pack(push, 1)
    struct NtpTimestamp {
        quint32 seconds;
        quint32 fraction;
        static inline NtpTimestamp fromDateTime(const QDateTime &dateTime);
        static inline QDateTime toDateTime(const NtpTimestamp &ntpTime);
    };
#pragma pack(pop)
    NtpTimestamp NtpTimestamp::fromDateTime(const QDateTime &dateTime) {
        qint64 ntpMSecs = dateTime.toMSecsSinceEpoch() - detail::january_1_1900;
        quint32 seconds = ntpMSecs / 1000;
        quint32 fraction = 0x100000000ll * (ntpMSecs % 1000) / 1000;
        NtpTimestamp result;
        result.seconds = qToBigEndian(seconds);
        result.fraction = qToBigEndian(fraction);
        return result;
    }

    QDateTime NtpTimestamp::toDateTime(const NtpTimestamp &ntpTime) {
        quint32 seconds = qFromBigEndian(ntpTime.seconds);
        quint32 fraction = qFromBigEndian(ntpTime.fraction);
        qint64 ntpMSecs = seconds * 1000ll + fraction * 1000ll / 0x100000000ll;
        return QDateTime::fromMSecsSinceEpoch(ntpMSecs + detail::january_1_1900);
    }
    struct NtpPacketFlags {
        unsigned char mode : 3;
        unsigned char versionNumber : 3;
        unsigned char leapIndicator : 2;
    };

#pragma pack(push, 1)
    struct NtpPacket {
        NtpPacketFlags flags;
        quint8 stratum;
        qint8 poll;
        qint8 precision;
        qint32 rootDelay;
        qint32 rootDispersion;
        qint8 referenceID[4];
        NtpTimestamp referenceTimestamp;
        NtpTimestamp originateTimestamp;
        NtpTimestamp receiveTimestamp;
        NtpTimestamp transmitTimestamp;
    };

    struct NtpAuthenticationInfo {
        quint32 keyId;
        quint8 messageDigest[16];
    };

    struct NtpFullPacket {
        NtpPacket basic;
        NtpAuthenticationInfo auth;
    };
#pragma pack(pop)

    class NtpReplyPrivate : public QSharedData {
    public:
        NtpFullPacket packet;
        QDateTime destinationTime;
    };

    class NtpReply {
    public:
        NtpReply() : d(new NtpReplyPrivate()) {
            std::memset(&d->packet, 0, sizeof(d->packet));
        }
        NtpReply(const NtpReply &other) : d(other.d){}
        ~NtpReply() {}

        NtpReply &operator=(const NtpReply &other) {
            d = other.d;
            return *this;
        }

        QDateTime destinationTime() const{
            return d->destinationTime;
        }

        bool isNull() const{
            return d->destinationTime.isNull();
        }

    protected:
        friend class NtpClient;

        NtpReply(NtpReplyPrivate *dd) : d(dd) {
            Q_ASSERT(dd != NULL);
        }
    private:
        QSharedDataPointer<NtpReplyPrivate> d;
    };

    class NtpClient : public QObject{
    public:
        NtpClient(QObject *parent = nullptr) : QObject(parent) {
            mSocket = new QUdpSocket(this);
            mSocket->bind(QHostAddress(QHostAddress::Any), QUdpSocket::PauseNever);
        }
        virtual ~NtpClient() { }

        bool sendRequest(const QHostAddress &address, quint16 port) {
            if (mSocket->state() != QAbstractSocket::BoundState)
                return false;
            NtpPacket packet;
            std::memset(&packet, 0, sizeof(packet));
            packet.flags.mode = ClientMode;
            packet.flags.versionNumber = 4;
            packet.transmitTimestamp = NtpTimestamp::fromDateTime(QDateTime::currentDateTimeUtc());

            if (mSocket->writeDatagram(reinterpret_cast<const char *>(&packet), sizeof(packet), address, port) < 0)
                return false;

            return true;
        }

        NtpReply sendRequestBlock(const QHostAddress &address, quint16 port, int timeoutMSec)
        {
            if (!sendRequest(address, port))
                return NtpReply();

            if (!mSocket->waitForReadyRead(timeoutMSec))
                return NtpReply();

            return readDatagrams();
        }

    private:
        NtpReply readDatagrams() {
            while (mSocket->hasPendingDatagrams()) {
                NtpFullPacket packet;
                std::memset(&packet, 0, sizeof(packet));

                QHostAddress address;
                quint16 port;

                if (mSocket->readDatagram(reinterpret_cast<char *>(&packet), sizeof(packet), &address, &port) < sizeof(NtpPacket))
                    continue;

                QDateTime now = QDateTime::currentDateTime();

                NtpReplyPrivate *replyPrivate = new NtpReplyPrivate();
                replyPrivate->packet = packet;
                replyPrivate->destinationTime = now;
                NtpReply reply(replyPrivate);
                return reply;
            }
            return NtpReply();
        }
        QUdpSocket *mSocket;
    };
}

class NetworkTime {
public:
    static QDateTime current() {
        QStringList ntpServerUrls;
        ntpServerUrls << "s1a.time.edu.cn";
        ntpServerUrls << "s1b.time.edu.cn";
        ntpServerUrls << "s1c.time.edu.cn";
        ntpServerUrls << "s1d.time.edu.cn";
        ntpServerUrls << "s1e.time.edu.cn";

        qntp::NtpClient ntpClient;
        for (QString url : ntpServerUrls) {
            QHostInfo hi = QHostInfo::fromName(url);
            for (QHostAddress ha : hi.addresses()) {
                qntp::NtpReply reply = ntpClient.sendRequestBlock(ha, 123, 1000);
                if (!reply.isNull())
                    return reply.destinationTime();
            }
        }
        return QDateTime();
    }
};
#endif // NETWORK_TIME_H
