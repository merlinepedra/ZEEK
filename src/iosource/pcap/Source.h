// See the file "COPYING" in the main distribution directory for copyright.

#ifndef IOSOURCE_PKTSRC_PCAP_SOURCE_H
#define IOSOURCE_PKTSRC_PCAP_SOURCE_H

#include "../PktSrc.h"

namespace iosource {
namespace pcap {

class PcapSource : public iosource::PktSrc {
public:
	// XXX
	PcapSource(const std::string& path, const std::string& filter, bool is_live);

	virtual ~PcapSource();

	static PktSrc* Instantiate(const std::string& path, const std::string& filter, bool is_live);

protected:
	// PktSrc interface.
	virtual void Open();
	virtual void Close();
	virtual int ExtractNextPacket(Packet* pkt);
	virtual void DoneWithPacket(Packet* pkt);
	virtual int PrecompileFilter(int index, const std::string& filter);
	virtual int SetFilter(int index);
	virtual void Statistics(Stats* stats);
	virtual bool GetCurrentPacket(const pcap_pkthdr** hdr, const u_char** pkt);

private:
	void OpenLive();
	void OpenOffline();
	void PcapError();
	void SetHdrSize();

	Properties props;
	Stats stats;

	pcap_t *pd;

	struct pcap_pkthdr current_hdr;
	struct pcap_pkthdr last_hdr;
	const u_char* last_data;
};

}
}

#endif
