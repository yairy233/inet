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
            auto protTag = pck->getTag<PacketProtocolTag>();
            if (protTag != nullptr)
                out << formatPacket(pck, protTag->getProtocol());
            else
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

std::string InetPacketPrinter3::formatPacket(Packet *pk, const Protocol *protocol) const
{
    std::ostringstream os;

    if (*protocol == Protocol::ieee80211) {
        // FIXME what about non-data frames like management frames?
        const auto ieee80211MacHeader = pk->popHeader<ieee80211::Ieee80211DataHeader>(b(-1), Chunk::PF_ALLOW_INCOMPLETE | Chunk::PF_ALLOW_NULLPTR | Chunk::PF_ALLOW_IMPROPERLY_REPRESENTED | Chunk::PF_ALLOW_INCORRECT | Chunk::PF_ALLOW_SERIALIZATION);
        const auto ieee80211MacTrailer = pk->popTrailer<ieee80211::Ieee80211MacTrailer>(B(4), Chunk::PF_ALLOW_INCOMPLETE | Chunk::PF_ALLOW_NULLPTR | Chunk::PF_ALLOW_IMPROPERLY_REPRESENTED | Chunk::PF_ALLOW_INCORRECT | Chunk::PF_ALLOW_SERIALIZATION);

        if (ieee80211MacHeader == nullptr) {
             // fallback to generic case or throw error?
        } else {
            if (ieee80211MacHeader->isIncomplete()) {
                // TODO test for incorrect / improper presentation
            } else {
                os << formatIeee80211MacHeader(ieee80211MacHeader.get());
                os << formatPacket(pk, &Protocol::ieee8022); // FIXME: for now LLC/SNAP header
            }
        }
        os << formatIeee80211MacTrailer(ieee80211MacTrailer.get());
    }
    if (*protocol == Protocol::ieee8022) {
        // FIXME handle Llc header too, not just LlcWithSnap (see Ieee8022Llc::decapsulate)
        const auto ieee8022LlcSnapHeader = pk->popHeader<Ieee8022LlcSnapHeader>(b(-1), Chunk::PF_ALLOW_INCOMPLETE | Chunk::PF_ALLOW_NULLPTR | Chunk::PF_ALLOW_IMPROPERLY_REPRESENTED | Chunk::PF_ALLOW_INCORRECT | Chunk::PF_ALLOW_SERIALIZATION);

        if (ieee8022LlcSnapHeader == nullptr) {
             // fallback to generic case or throw error?
        } else {
            if (ieee8022LlcSnapHeader->isIncomplete()) {
                // TODO test for incorrect / improper presentation
            } else {
                os << format8022LlcHeader(ieee8022LlcSnapHeader.get());
                os << formatPacket(pk, ProtocolGroup::ethertype.findProtocol(ieee8022LlcSnapHeader->getProtocolId()));
            }
        }
    }
    else if (*protocol == Protocol::ipv4) {
        b dataLength = pk->getDataLength();
        const auto ipv4Header = pk->popHeader<Ipv4Header>(b(-1), Chunk::PF_ALLOW_INCOMPLETE | Chunk::PF_ALLOW_NULLPTR | Chunk::PF_ALLOW_IMPROPERLY_REPRESENTED | Chunk::PF_ALLOW_INCORRECT | Chunk::PF_ALLOW_SERIALIZATION);
        b ipLength = B(ipv4Header->getTotalLengthField());
        b padding = dataLength - ipLength;
        if (padding > b(0))
            pk->setTrailerPopOffset(pk->getTrailerPopOffset()-padding);

        if (ipv4Header == nullptr)
            ; // fallback to generic case or throw error?
        else {
            if (ipv4Header->isIncomplete())
                ; // TODO test for incorrect / improper presentation
            else {
                os << formatIpv4Header(ipv4Header.get());
                os << formatPacket(pk, ipv4Header->getProtocol());
            }
        }
        if (padding > b(0))
            os << "[PADDING " << padding <<"]";
    }
    else if (*protocol == Protocol::icmpv4) {
        const auto icmpHeader = pk->popHeader<IcmpHeader>(b(-1), Chunk::PF_ALLOW_INCOMPLETE | Chunk::PF_ALLOW_NULLPTR | Chunk::PF_ALLOW_IMPROPERLY_REPRESENTED | Chunk::PF_ALLOW_INCORRECT | Chunk::PF_ALLOW_SERIALIZATION);
        if (icmpHeader == nullptr)
            ; // fallback to generic case or throw error?
        else {
            if (icmpHeader->isIncomplete())
                ; // TODO test for incorrect / improper presentation
            else {
                os << formatICMPHeader(icmpHeader.get());
                os << formatPacket(pk);
            }
        }
    }
    else
        os << formatPacket(pk);  // fall back to printing based on chunk types

    return os.str();
}

std::string InetPacketPrinter3::formatPacket(Packet *packet) const
{
    std::string outs;

    //reset mutable variables
    srcAddr.reset();
    destAddr.reset();

    std::ostringstream out;
    while (auto chunkref = packet->popHeader(b(-1), Chunk::PF_ALLOW_NULLPTR)) {
        const auto chunk = chunkref.get();
        std::ostringstream out;

        //TODO slicechunk???

        if (const NetworkHeaderBase *l3Header = dynamic_cast<const NetworkHeaderBase *>(chunk)) {
            srcAddr = l3Header->getSourceAddress();
            destAddr = l3Header->getDestinationAddress();
#ifdef WITH_IPv4
            if (const auto *ipv4Header = dynamic_cast<const Ipv4Header *>(chunk)) {
                out << formatIpv4Header(ipv4Header);
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
            out << formatTCPHeader(tcpHeader);
        }
#endif // ifdef WITH_TCP_COMMON
#ifdef WITH_UDP
        else if (const auto udpHeader = dynamic_cast<const UdpHeader *>(chunk)) {
            out << formatUDPHeader(udpHeader);
        }
#endif // ifdef WITH_UDP
#ifdef WITH_IPv4
        else if (const auto icmpHeader = dynamic_cast<const IcmpHeader *>(chunk)) {
            out << formatICMPHeader(icmpHeader);
        }
        else if (const auto arp = dynamic_cast<const ArpPacket *>(chunk)) {
            out << formatARPHeader(arp);
        }
#endif // ifdef WITH_IPv4
#ifdef WITH_IEEE80211
        else if (const auto ieee80211PhyHdr = dynamic_cast<const physicallayer::Ieee80211PhyHeader *>(chunk)) {
            out << formatIeee80211PhyHeader(ieee80211PhyHdr);
        }
        else if (const auto ieee80211MacHdr = dynamic_cast<const ieee80211::Ieee80211MacHeader *>(chunk)) {
            out << formatIeee80211MacHeader(ieee80211MacHdr);
        }
#endif // ifdef WITH_IEEE80211
#ifdef WITH_RIP
        else if (const auto rip = dynamic_cast<const RipPacket *>(chunk)) {
            out << formatRIPheader(rip);
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
        outs += out.str();
    }
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
std::string InetPacketPrinter3::formatIpv4Header(const Ipv4Header *chunk) const
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

std::string InetPacketPrinter3::formatARPHeader(const ArpPacket *chunk) const
{
    std::ostringstream os;
    switch (chunk->getOpcode()) {
        case ARP_REQUEST:
            os << "ARP req: " << chunk->getDestIPAddress()
               << "=? (s=" << chunk->getSrcIPAddress() << "(" << chunk->getSrcMACAddress() << "))";
            break;

        case ARP_REPLY:
            os << "ARP reply: "
               << chunk->getSrcIPAddress() << "=" << chunk->getSrcMACAddress()
               << " (d=" << chunk->getDestIPAddress() << "(" << chunk->getDestMACAddress() << "))"
            ;
            break;

        case ARP_RARP_REQUEST:
            os << "RARP req: " << chunk->getDestMACAddress()
               << "=? (s=" << chunk->getSrcIPAddress() << "(" << chunk->getSrcMACAddress() << "))";
            break;

        case ARP_RARP_REPLY:
            os << "RARP reply: "
               << chunk->getSrcMACAddress() << "=" << chunk->getSrcIPAddress()
               << " (d=" << chunk->getDestIPAddress() << "(" << chunk->getDestMACAddress() << "))";
            break;

        default:
            os << "ARP op=" << chunk->getOpcode() << ": d=" << chunk->getDestIPAddress()
               << "(" << chunk->getDestMACAddress()
               << ") s=" << chunk->getSrcIPAddress()
               << "(" << chunk->getSrcMACAddress() << ")";
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

std::string InetPacketPrinter3::formatIeee80211MacTrailer(const ieee80211::Ieee80211MacTrailer *chunk) const
{
    std::ostringstream os;
    os << "[802.11 Trailer " << chunk->getChunkLength() << "]";
    return os.str();
}

std::string InetPacketPrinter3::formatIeee80211MacHeader(const ieee80211::Ieee80211MacHeader *chunk) const
{
    using namespace ieee80211;

    std::ostringstream os;
    os << "[802.11 ";
    switch (chunk->getType()) {
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
            os << "type=" << chunk->getType();
            break;
    }
    const auto twoAddressHeader = dynamic_cast<const Ieee80211TwoAddressHeader *>(chunk);
    if (twoAddressHeader) {
        os << " " << twoAddressHeader->getTransmitterAddress() << ">" << chunk->getReceiverAddress();
    } else {
        os << " " << chunk->getReceiverAddress();
    }
    os << "]";
    return os.str();
}
#endif // ifdef WITH_IEEE80211

#ifdef WITH_TCP_COMMON
std::string InetPacketPrinter3::formatTCPHeader(const tcp::TcpHeader *chunk) const
{
    std::ostringstream os;
    os << "[TCP " << chunk->getSrcPort() << ">" << chunk->getDestPort() << " ";
    // flags
    bool flags = false;
    if (chunk->getUrgBit()) {
        flags = true;
        os << "U";
    }
    if (chunk->getAckBit()) {
        flags = true;
        os << "A";
    }
    if (chunk->getPshBit()) {
        flags = true;
        os << "P";
    }
    if (chunk->getRstBit()) {
        flags = true;
        os << "R";
    }
    if (chunk->getSynBit()) {
        flags = true;
        os << "S";
    }
    if (chunk->getFinBit()) {
        flags = true;
        os << "F";
    }
    if (!flags) {
        os << "-";
    }

    // data-seqno
    os << " seq=" << chunk->getSequenceNo();

    // ack
    if (chunk->getAckBit())
        os << " ack=" << chunk->getAckNo();

    // window
    os << " win=" << chunk->getWindow();

    // urgent
    if (chunk->getUrgBit())
        os << " urg=" << chunk->getUrgentPointer();

    os << "]";
    return os.str();
}
#endif // ifdef WITH_TCP_COMMON

#ifdef WITH_UDP
std::string InetPacketPrinter3::formatUDPHeader(const UdpHeader *chunk) const
{
    std::ostringstream os;
    os << "[UDP " << chunk->getSourcePort() << ">" << chunk->getDestinationPort() << "]";
    return os.str();
}
#endif // ifdef WITH_UDP

#ifdef WITH_IPv4
std::string InetPacketPrinter3::formatICMPHeader(const IcmpHeader *chunk) const
{
    std::ostringstream os;
    switch (chunk->getType()) {
        case ICMP_ECHO_REQUEST:
            os << "[ICMP req";
            if (auto echo = dynamic_cast<const IcmpEchoRequest *>(chunk))
                os << " id=" << echo->getIdentifier() << " seq=" << echo->getSeqNumber() << "]";
            break;

        case ICMP_ECHO_REPLY:
            os << "[ICMP rep";
            if (auto echo = dynamic_cast<const IcmpEchoReply *>(chunk))
                os << " id=" << echo->getIdentifier() << " seq=" << echo->getSeqNumber() << "]";
            break;

        case ICMP_DESTINATION_UNREACHABLE:
            os << "ICMP unreachable code=" << chunk->getCode() << "]";
            break;

        default:
            os << "[ICMP type=" << chunk->getType() << " code=" << chunk->getCode() << "]";
            break;
    }
    return os.str();
}
#endif // ifdef WITH_IPv4

#ifdef WITH_RIP
std::string InetPacketPrinter3::formatRIPheader(const RipPacket *chunk) const
{
    std::ostringstream os;
    os << "RIP: ";
    switch (chunk->getCommand()) {
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
    unsigned int size = chunk->getEntryArraySize();
    for (unsigned int i = 0; i < size; ++i) {
        const RipEntry& entry = chunk->getEntry(i);
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

