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

#include "InetPacketPrinter3.h"

namespace inet {

Register_MessagePrinter(InetPacketPrinter3);

static const char INFO_SEPAR[] = " ";

int InetPacketPrinter3::getScoreFor(cMessage *msg) const
{
                return msg->isPacket() ? 21 : 0;
}

void InetPacketPrinter3::printMessage(std::ostream& os, cMessage *msg) const
{
    std::string outs;

    //reset mutable variables
    srcAddr.reset();
    destAddr.reset();

    const char *separ = "";
    for (cPacket *pk = dynamic_cast<cPacket *>(msg); pk; pk = pk->getEncapsulatedPacket()) {
        std::ostringstream out;
        if (Packet *pck = dynamic_cast<Packet*>(pk)) {
            out << formatPacket(pck);
        }
        else
            out << separ << pk->getClassName() << ":" << pk->getByteLength() << " bytes";
        out << separ << outs;
        outs = out.str();
        separ = INFO_SEPAR;
    }
    os << outs;
}

std::string InetPacketPrinter3::formatPacket2(Packet *pk, const Protocol& protocol) const
{
    if (protocol == Protocol::ipv4) {
        auto ipv4Header = pk->popHeader<Ipv4Header>(Chunk::PF_ALLOW_INCOMPETE | Chunk::PF_ALLOW_NULLPTR ...);
        // masutt lehet egy trailert is le kell szedni
        if (ipv4Header == nullptr)
            ; // fallback to generic case
        else {
            if (ipv4Header->isIncomplete())
                ;
            else {
                fromatIpv4Header(ipv4Header);
                formatPacket2(pk, ipv4Header->getProtocol());
            }
        }
    }
    else ;//...
}

std::string InetPacketPrinter3::formatPacket(Packet *pk) const
{
    std::string outs;

    //reset mutable variables
    srcAddr.reset();
    destAddr.reset();

    std::ostringstream out;
    const char *separ = "";
    auto packet = new Packet(pk->getName(), pk->peekData());
    while (auto chunkref = packet->popHeader(b(-1), Chunk::PF_ALLOW_NULLPTR)) {
        const auto chunk = chunkref.get();
        std::ostringstream out;

        //TODO slicechunk???

        if (const NetworkHeaderBase *l3Header = dynamic_cast<const NetworkHeaderBase *>(chunk)) {
            srcAddr = l3Header->getSourceAddress();
            destAddr = l3Header->getDestinationAddress();
#ifdef WITH_IPv4
            if (const auto *ipv4Header = dynamic_cast<const Ipv4Header *>(chunk)) {
                out << formatIpv4Packet(ipv4Header);
            }
            else
#endif // ifdef WITH_IPv4
                out << chunk->getClassName() << ": " << srcAddr << " > " << destAddr;
        }
        else if (const auto llcHeader = dynamic_cast<const Ieee8022LlcHeader *>(chunk)) {
            out << format8022LlcHeader(llcHeader);
        }
#ifdef WITH_ETHERNET
        else if (const auto eth = dynamic_cast<const EthernetMacHeader *>(chunk)) {
            out << "ETH: " << eth->getSrc() << " > " << eth->getDest();
            if (const auto tc = packet->peekTrailer(b(-1), Chunk::PF_ALLOW_NULLPTR).get())
                if (typeid(*tc) == typeid(EthernetFcs)) {
                    const auto& fcs = packet->popTrailer<EthernetFcs>();
                    (void)fcs;    //TODO do we show the FCS?
                }
            //FIXME llc/qtag/snap/...
        }
#endif // ifdef WITH_ETHERNET
#ifdef WITH_TCP_COMMON
        else if (const auto tcpHeader = dynamic_cast<const tcp::TcpHeader *>(chunk)) {
            out << formatTCPPacket(tcpHeader);
        }
#endif // ifdef WITH_TCP_COMMON
#ifdef WITH_UDP
        else if (const auto udpHeader = dynamic_cast<const UdpHeader *>(chunk)) {
            out << formatUDPPacket(udpHeader);
        }
#endif // ifdef WITH_UDP
#ifdef WITH_IPv4
        else if (const auto ipv4Header = dynamic_cast<const IcmpHeader *>(chunk)) {
            out << formatICMPPacket(ipv4Header);
        }
        else if (const auto arp = dynamic_cast<const ArpPacket *>(chunk)) {
            out << formatARPPacket(arp);
        }
#endif // ifdef WITH_IPv4
#ifdef WITH_IEEE80211
        else if (const auto ieee80211PhyHdr = dynamic_cast<const physicallayer::Ieee80211PhyHeader *>(chunk)) {
            out << formatIeee80211PhyHeader(ieee80211PhyHdr);
        }
        else if (const auto ieee80211MacHdr = dynamic_cast<const ieee80211::Ieee80211MacHeader *>(chunk)) {
            out << formatIeee80211Frame(ieee80211MacHdr);
        }
#endif // ifdef WITH_IEEE80211
#ifdef WITH_RIP
        else if (const auto rip = dynamic_cast<const RipPacket *>(chunk)) {
            out << formatRIPPacket(rip);
        }
#endif // ifdef WITH_RIP
#ifdef WITH_RADIO
        else if (const auto signal = dynamic_cast<const Signal *>(chunk)) {
            out << formatSignal(signal);
        }
#endif // ifdef WITH_RADIO
        else if (chunk->getChunkType() == Chunk::CT_BITCOUNT || chunk->getChunkType() == Chunk::CT_BITS ||
                 chunk->getChunkType() == Chunk::CT_BYTECOUNT || chunk->getChunkType() == Chunk::CT_BYTES) {
            out << "[DATA " << chunk->getChunkLength() << "]";
        } else {
            out << "[?" << chunk->getChunkLength() << "]";
        }
// reverse order?
//        out << separ << outs;
//        outs = out.str();
        outs += out.str();
        separ = INFO_SEPAR;
    }
    delete packet;
    return outs;
}

std::string InetPacketPrinter3::format8022LlcHeader(const Ieee8022LlcHeader *chunk) const
{
    std::ostringstream os;
    const auto ieee8022Snap = dynamic_cast<const Ieee8022LlcSnapHeader *>(chunk);
    if (ieee8022Snap) {
        os << "[SNAP prot=" << ieee8022Snap->getProtocolId();
    } else { // LLC
        os << "[LLC";
    }
    os << "]";
    return os.str();
}

#ifdef WITH_IPv4
std::string InetPacketPrinter3::formatIpv4Packet(const Ipv4Header *chunk) const
{
    std::ostringstream os;
    os << "[Ipv4 " << chunk->getSourceAddress() << ">" << chunk->getDestinationAddress();
    if (chunk->getMoreFragments() || chunk->getFragmentOffset() > 0) {
        os << " " << (chunk->getMoreFragments() ? "" : "last ")
            << "fragment with offset=" << chunk->getFragmentOffset() << " of ";
    }
    os << "]";
    return os.str();
}

std::string InetPacketPrinter3::formatARPPacket(const ArpPacket *packet) const
{
    std::ostringstream os;
    switch (packet->getOpcode()) {
        case ARP_REQUEST:
            os << "ARP req: " << packet->getDestIPAddress()
               << "=? (s=" << packet->getSrcIPAddress() << "(" << packet->getSrcMACAddress() << "))";
            break;

        case ARP_REPLY:
            os << "ARP reply: "
               << packet->getSrcIPAddress() << "=" << packet->getSrcMACAddress()
               << " (d=" << packet->getDestIPAddress() << "(" << packet->getDestMACAddress() << "))"
            ;
            break;

        case ARP_RARP_REQUEST:
            os << "RARP req: " << packet->getDestMACAddress()
               << "=? (s=" << packet->getSrcIPAddress() << "(" << packet->getSrcMACAddress() << "))";
            break;

        case ARP_RARP_REPLY:
            os << "RARP reply: "
               << packet->getSrcMACAddress() << "=" << packet->getSrcIPAddress()
               << " (d=" << packet->getDestIPAddress() << "(" << packet->getDestMACAddress() << "))";
            break;

        default:
            os << "ARP op=" << packet->getOpcode() << ": d=" << packet->getDestIPAddress()
               << "(" << packet->getDestMACAddress()
               << ") s=" << packet->getSrcIPAddress()
               << "(" << packet->getSrcMACAddress() << ")";
            break;
    }
    return os.str();
}
#endif // ifdef WITH_IPv4

#ifdef WITH_IEEE80211
std::string InetPacketPrinter3::formatIeee80211PhyHeader(const physicallayer::Ieee80211PhyHeader *chunk) const
{
    using namespace physicallayer;
    std::ostringstream os;
    os << "[802.11PHY " << chunk->getChunkLength() << "]";
    return os.str();
}

std::string InetPacketPrinter3::formatIeee80211Frame(const ieee80211::Ieee80211MacHeader *packet) const
{
    using namespace ieee80211;

    std::ostringstream os;
    os << "[802.11 ";
    switch (packet->getType()) {
        case ST_ASSOCIATIONREQUEST:
            os << "assocReq";
            break;

        case ST_ASSOCIATIONRESPONSE:
            os << "assocResp";
            break;

        case ST_REASSOCIATIONREQUEST:
            os << "reassocReq";
            break;

        case ST_REASSOCIATIONRESPONSE:
            os << "reassocResp";
            break;

        case ST_PROBEREQUEST:
            os << "probeReq";
            break;

        case ST_PROBERESPONSE:
            os << "probeResp";
            break;

        case ST_BEACON:
            os << "beacon";
            break;

        case ST_ATIM:
            os << "atim";
            break;

        case ST_DISASSOCIATION:
            os << "disAssoc";
            break;

        case ST_AUTHENTICATION:
            os << "auth";
            break;

        case ST_DEAUTHENTICATION:
            os << "deAuth";
            break;

        case ST_ACTION:
            os << "action";
            break;

        case ST_NOACKACTION:
            os << "noAckAction";
            break;

        case ST_PSPOLL:
            os << "psPoll";
            break;

        case ST_RTS: {
            os << "rts";
            break;
        }

        case ST_CTS:
            os << "cts";
            break;

        case ST_ACK:
            os << "ack";
            break;

        case ST_BLOCKACK_REQ:
            os << "blockAckReq";
            break;

        case ST_BLOCKACK:
            os << "blockAck";
            break;

        case ST_DATA:
            os << "data";
            break;

        case ST_DATA_WITH_QOS:
            os << "dataQos";
            break;

        case ST_LBMS_REQUEST:
            os << "lbmsReq";
            break;

        case ST_LBMS_REPORT:
            os << "lbmsReport";
            break;

        default:
            os << "type=" << packet->getType();
            break;
    }
    const auto twoAddressHeader = dynamic_cast<const Ieee80211TwoAddressHeader *>(packet);
    if (twoAddressHeader) {
        os << " " << twoAddressHeader->getTransmitterAddress() << ">" << packet->getReceiverAddress();
    } else {
        os << " " << packet->getReceiverAddress();
    }
    os << "]";
    return os.str();
}
#endif // ifdef WITH_IEEE80211

#ifdef WITH_TCP_COMMON
std::string InetPacketPrinter3::formatTCPPacket(const tcp::TcpHeader *tcpSeg) const
{
    std::ostringstream os;
    os << "[TCP " << tcpSeg->getSrcPort() << ">" << tcpSeg->getDestPort() << " ";
    // flags
    bool flags = false;
    if (tcpSeg->getUrgBit()) {
        flags = true;
        os << "U";
    }
    if (tcpSeg->getAckBit()) {
        flags = true;
        os << "A";
    }
    if (tcpSeg->getPshBit()) {
        flags = true;
        os << "P";
    }
    if (tcpSeg->getRstBit()) {
        flags = true;
        os << "R";
    }
    if (tcpSeg->getSynBit()) {
        flags = true;
        os << "S";
    }
    if (tcpSeg->getFinBit()) {
        flags = true;
        os << "F";
    }
    if (!flags) {
        os << "-";
    }

    // data-seqno
    os << " seq=" << tcpSeg->getSequenceNo();

    // ack
    if (tcpSeg->getAckBit())
        os << " ack=" << tcpSeg->getAckNo();

    // window
    os << " win=" << tcpSeg->getWindow();

    // urgent
    if (tcpSeg->getUrgBit())
        os << " urg=" << tcpSeg->getUrgentPointer();

    os << "]";
    return os.str();
}
#endif // ifdef WITH_TCP_COMMON

#ifdef WITH_UDP
std::string InetPacketPrinter3::formatUDPPacket(const UdpHeader *udpPacket) const
{
    std::ostringstream os;
    os << "[UDP " << udpPacket->getSourcePort() << ">" << udpPacket->getDestinationPort() << "]";
    return os.str();
}
#endif // ifdef WITH_UDP

//std::string InetPacketPrinter3::formatPingPayload(const PingPayload *packet) const
//{
//    std::ostringstream os;
//    os << "PING ";
//#ifdef WITH_IPv4
//    IcmpHeader *owner = dynamic_cast<IcmpHeader *>(packet->getOwner());
//    if (owner) {
//        switch (owner->getType()) {
//            case ICMP_ECHO_REQUEST:
//                os << "req ";
//                break;
//
//            case ICMP_ECHO_REPLY:
//                os << "reply ";
//                break;
//
//            default:
//                break;
//        }
//    }
//#endif // ifdef WITH_IPv4
//    os << srcAddr << " to " << destAddr
//       << " (" << packet->getByteLength() << " bytes) id=" << packet->getId()
//       << " seq=" << packet->getSeqNo();
//
//    return os.str();
//}

#ifdef WITH_IPv4
std::string InetPacketPrinter3::formatICMPPacket(const IcmpHeader *icmpHeader) const
{
    std::ostringstream os;
    switch (icmpHeader->getType()) {
        case ICMP_ECHO_REQUEST:
            os << "[ICMP req";
            if (auto echo = dynamic_cast<const IcmpEchoRequest *>(icmpHeader))
                os << " id=" << echo->getIdentifier() << " seq=" << echo->getSeqNumber() << "]";
            break;

        case ICMP_ECHO_REPLY:
            os << "[ICMP rep";
            if (auto echo = dynamic_cast<const IcmpEchoReply *>(icmpHeader))
                os << " id=" << echo->getIdentifier() << " seq=" << echo->getSeqNumber() << "]";
            break;

        case ICMP_DESTINATION_UNREACHABLE:
            os << "ICMP unreachable code=" << icmpHeader->getCode() << "]";
            break;

        default:
            os << "[ICMP type=" << icmpHeader->getType() << " code=" << icmpHeader->getCode() << "]";
            break;
    }
    return os.str();
}
#endif // ifdef WITH_IPv4

#ifdef WITH_RIP
std::string InetPacketPrinter3::formatRIPPacket(const RipPacket *packet) const
{
    std::ostringstream os;
    os << "RIP: ";
    switch (packet->getCommand()) {
        case RIP_REQUEST:
            os << "req ";
            break;

        case RIP_RESPONSE:
            os << "resp ";
            break;

        default:
            os << "unknown ";
            break;
    }
    unsigned int size = packet->getEntryArraySize();
    for (unsigned int i = 0; i < size; ++i) {
        const RipEntry& entry = packet->getEntry(i);
        if (i > 0)
            os << "; ";
        if (i > 2) {
            os << "...(" << size << " entries)";
            break;
        }
        os << entry.address << "/" << entry.prefixLength;
        if (!entry.nextHop.isUnspecified())
            os << "->" << entry.nextHop;
        if (entry.metric == 16)
            os << " unroutable";
        else
            os << " m=" << entry.metric;
    }
    return os.str();
}
#endif // ifdef WITH_RIP

#ifdef WITH_RADIO
std::string InetPacketPrinter3::formatSignal(const Signal *packet) const
{
    std::ostringstream os;
    // Note: Do NOT try to print transmission's properties here! getTransmission() will likely
    // return an invalid pointer here, because the transmission is no longer kept in the Medium.
    // const ITransmission *transmission = packet->getTransmission();
    os << "SIG " << SIMTIME_DBL(packet->getDuration()) * 1000 << "ms: ";
    return os.str();
}
#endif // ifdef WITH_RADIO

} // namespace inet

