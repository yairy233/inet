//
// Copyright (C) 2014 OpenSim Ltd.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

#include "inet/common/INETDefs.h"

#include "inet/common/packet/Packet.h"
#include "inet/networklayer/common/L3Address.h"

#ifdef WITH_ETHERNET
#include "inet/linklayer/ethernet/EtherFrame_m.h"
#endif // ifdef WITH_ETHERNET

#include "inet/linklayer/ieee8022/Ieee8022LlcHeader_m.h"

#ifdef WITH_IPv4
#include "inet/networklayer/arp/ipv4/ArpPacket_m.h"
#include "inet/networklayer/ipv4/IcmpHeader.h"
#include "inet/networklayer/ipv4/Ipv4Header.h"
#endif // ifdef WITH_IPv4

#ifdef WITH_TCP_COMMON
#include "inet/transportlayer/tcp_common/TcpHeader.h"
#endif // ifdef WITH_TCP_COMMON

#ifdef WITH_UDP
#include "inet/transportlayer/udp/UdpHeader_m.h"
#endif // ifdef WITH_UDP

#ifdef WITH_IEEE80211
#include "inet/physicallayer/ieee80211/packetlevel/Ieee80211PhyHeader_m.h"
#include "inet/linklayer/ieee80211/mac/Ieee80211Frame_m.h"
#endif // ifdef WITH_IEEE80211

#include "inet/networklayer/contract/NetworkHeaderBase_m.h"

#ifdef WITH_RIP
#include "inet/routing/rip/RipPacket_m.h"
#endif // ifdef WITH_RIP

#ifdef WITH_RADIO
#include "inet/physicallayer/common/packetlevel/Signal.h"
#include "inet/physicallayer/analogmodel/packetlevel/ScalarTransmission.h"
#endif // ifdef WITH_RADIO

namespace inet {

#ifdef WITH_RADIO
using namespace physicallayer;
#endif // ifdef WITH_RADIO

class INET_API InetPacketPrinter3 : public cMessagePrinter
{
  protected:
    mutable L3Address srcAddr;
    mutable L3Address destAddr;

  public:
    std::string format8022LlcHeader(const Ieee8022LlcHeader *chunk) const;
#ifdef WITH_IPv4
    std::string formatIpv4Header(const Ipv4Header *chunk) const;
    std::string formatARPHeader(const ArpPacket *chunk) const;
    std::string formatICMPHeader(const IcmpHeader *chunk) const;
#endif // ifdef WITH_IPv4
#ifdef WITH_RADIO
    std::string formatSignal(const Signal *signal) const;
#endif // ifdef WITH_RADIO
#ifdef WITH_IEEE80211
    std::string formatIeee80211PhyHeader(const physicallayer::Ieee80211PhyHeader *chunk) const;
    std::string formatIeee80211MacHeader(const ieee80211::Ieee80211MacHeader *chunk) const;
    std::string formatIeee80211MacTrailer(const ieee80211::Ieee80211MacTrailer *chunk) const;
#endif // ifdef WITH_IEEE80211
#ifdef WITH_RIP
    std::string formatRIPheader(const RipPacket *chunk) const;
#endif // ifdef WITH_RIP
#ifdef WITH_TCP_COMMON
    std::string formatTCPHeader(const tcp::TcpHeader *chunk) const;
#endif // ifdef WITH_TCP_COMMON
#ifdef WITH_UDP
    std::string formatUDPHeader(const UdpHeader *chunk) const;
#endif // ifdef WITH_UDP
    std::string formatPacket(Packet *pk, const Protocol *protocol) const;
    std::string formatPacket(Packet *packet) const;

  public:
    InetPacketPrinter3() {}
    virtual ~InetPacketPrinter3() {}
    virtual int getScoreFor(cMessage *msg) const override;
    virtual void printMessage(std::ostream& os, cMessage *msg) const override;
};

} // namespace inet

#include <stdio.h>
#include <iostream>
#include "inet/common/INETDefs.h"
#include "inet/common/packet/Packet.h"
#include "inet/common/packet/chunk/BytesChunk.h"
#include "inet/common/packet/chunk/ByteCountChunk.h"
#include "inet/common/packet/chunk/BitCountChunk.h"
#include "inet/common/packet/chunk/BitsChunk.h"
#include "inet/physicallayer/ieee80211/packetlevel/Ieee80211PhyHeader_m.h"
#include "inet/linklayer/ieee80211/mac/Ieee80211Frame_m.h"
#include "inet/linklayer/ieee8022/Ieee8022LlcHeader_m.h"
#include "inet/networklayer/ipv4/Ipv4Header_m.h"
#include "inet/networklayer/ipv4/IcmpHeader_m.h"

inline void test() {
    using namespace ::inet;
    InetPacketPrinter3 printer;

    const size_t ping_packet_length = 135;
/*
    // [802.11PHY 5 byte][802.11 data 0A-AA-00-00-00-04>0A-AA-00-00-00-02][SNAP prot=2048][Ipv4 192.168.1.1>192.168.2.41][ICMP req id=0 seq=7][DATA 56 byte][?4 byte][DATA 10 byte]
    uint8_t ping_packet_bytes[ping_packet_length] = {
    0x00,0x3C,0x00,0x00,0x00,0x08,0x02,0x00,0x2C,0x0A,0xAA,0x00,0x00,0x00,0x02,0x0A,
    0xAA,0x00,0x00,0x00,0x04,0x0A,0xAA,0x00,0x00,0x00,0x06,0x50,0x06,0xAA,0xAA,0x03,
    0x00,0x00,0x00,0x08,0x00,0x45,0x00,0x00,0x54,0x00,0x07,0x00,0x00,0x1F,0x01,0x17,
    0x28,0xC0,0xA8,0x01,0x01,0xC0,0xA8,0x02,0x29,0x08,0x00,0x0D,0x0E,0x00,0x00,0x00,
    0x07,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,
    0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,
    0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,
    0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0xCB,0xA3,0x3C,0x75,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
*/
    // [802.11 data 0A-AA-00-00-00-04>0A-AA-00-00-00-02][SNAP prot=2048][Ipv4 192.168.1.1>192.168.2.41][ICMP req id=0 seq=7][DATA 56 byte][?4 byte]
    uint8_t ping_packet_bytes[ping_packet_length] = {
    0x08,0x02,0x00,0x2C,0x0A,0xAA,0x00,0x00,0x00,0x02,0x0A,
    0xAA,0x00,0x00,0x00,0x04,0x0A,0xAA,0x00,0x00,0x00,0x06,0x50,0x06,0xAA,0xAA,0x03,
    0x00,0x00,0x00,0x08,0x00,0x45,0x00,0x00,0x54,0x00,0x07,0x00,0x00,0x1F,0x01,0x17,
    0x28,0xC0,0xA8,0x01,0x01,0xC0,0xA8,0x02,0x29,0x08,0x00,0x0D,0x0E,0x00,0x00,0x00,
    0x07,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,
    0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,
    0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,
    0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0xCB,0xA3,0x3C,0x75
    };

    const auto& bchunk = makeShared<BytesChunk>(ping_packet_bytes, ping_packet_length);
    Packet msg("PING", bchunk);
    msg.ensureTag<PacketProtocolTag>()->setProtocol(&Protocol::ieee80211);
    printer.printMessage(EV, &msg);

/*
    msg.setHeaderPopOffset(b(0));
    msg.setTrailerPopOffset(msg.getTotalLength());

//    const auto ofdmHeader = msg.popHeader<physicallayer::Ieee80211OfdmPhyHeader>(b(-1), Chunk::PF_ALLOW_SERIALIZATION);
//    const auto ofdmTrailer = msg.popTrailer<BitCountChunk>(b(80), Chunk::PF_ALLOW_SERIALIZATION);
    const auto ieee80211Header = msg.popHeader<ieee80211::Ieee80211DataHeader>(b(-1), Chunk::PF_ALLOW_SERIALIZATION);
    const auto ieee80211MacTrailer = msg.popTrailer<ieee80211::Ieee80211MacTrailer>(B(4), Chunk::PF_ALLOW_SERIALIZATION);
    const auto snapHeader = msg.popHeader<Ieee8022LlcSnapHeader>(b(-1), Chunk::PF_ALLOW_SERIALIZATION);
    const auto ipv4Header = msg.popHeader<Ipv4Header>(b(-1), Chunk::PF_ALLOW_SERIALIZATION);
    const auto icmpHeader = msg.popHeader<IcmpEchoRequest>(b(-1), Chunk::PF_ALLOW_SERIALIZATION);
    const auto data = msg.peekData<ByteCountChunk>();

    Packet msg2("PING2", data);
//    msg2.ensureTag<PacketProtocolTag>()->setProtocol(&Protocol::ieee80211);
    msg2.insertHeader(icmpHeader);
    msg2.insertHeader(ipv4Header);
    msg2.insertHeader(snapHeader);
    msg2.insertHeader(ieee80211Header);
//    msg2.insertHeader(ofdmHeader);
    msg2.insertTrailer(ieee80211MacTrailer);
//    msg2.insertTrailer(ofdmTrailer);

//    printer.printMessage(EV, &msg2);

*/
}
