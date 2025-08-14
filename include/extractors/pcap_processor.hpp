#ifndef PCAP_PROCESSOR_HPP
#define PCAP_PROCESSOR_HPP

#include <string>
#include <vector>
#include <map>
#include "json.hpp"

namespace pcap_processor {

struct PcapConfig {
    std::string input_file;           // Input PCAP file
    std::string output_file;          // Output CSV file
    std::vector<std::string> features; // Selected features to extract
    std::vector<std::string> bpf_filters; // BPF filters (e.g., "name=filter")
    std::string bpf_pre_filter;       // Pre-applied BPF filter
    std::string profile_file;         // JSON profile for custom features
    std::string label_file;           // JSON suspicion profile for labeling
    std::string reference_ip;         // Reference IP for direction
    bool verbose;                     // Verbose mode
    bool full_payload;                // Extract full payload
    bool allow_payload_filters;       // Allow payload filters without pre-filter
};

std::vector<std::string> profile_pcap(const std::string& input_file, const std::vector<std::string>& bpf_filters = {}, const std::string& profile_file = "");
void process_pcap(const PcapConfig& config);

} // namespace pcap_processor

#endif // PCAP_PROCESSOR_HPP