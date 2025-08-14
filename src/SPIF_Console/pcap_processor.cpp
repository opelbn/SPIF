#include "pcap_processor.hpp"
#include <pcap.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <set>
#include <mutex>
#include <iomanip>
#include "json.hpp"
#include "logslice.hpp"

#ifdef _WIN32
#define NOMINMAX
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

enum class Endian { Big, Little };

using json = nlohmann::json;

namespace pcap_processor {

static std::mutex out_mutex;

struct packetfeatures {
    float packet_size;
    float arrival_interval;
    float protocol;
    float dst_p;
    std::string src_ip;
    std::string dst_ip;
    std::vector<u_char> raw_payload;
    double timestamp;
    uint16_t transaction_id;
    uint8_t function_code;
    int payload_offset;
    int tcp_offset;
    std::vector<int> bpf_results;
    std::vector<std::pair<std::string, uint32_t>> named_payload_values;
    bool tcp_syn = false, tcp_ack = false, tcp_fin = false, tcp_rst = false, tcp_psh = false, tcp_urg = false;
    uint8_t ip_ttl = 0, ip_tos = 0;
    uint16_t tcp_window = 0;
    std::string direction;
    int label = 0;
};

std::vector<std::string> profile_pcap(const std::string& input_file, const std::vector<std::string>& bpf_filters, const std::string& profile_file) {
    std::set<std::string> valid_features = {
        "packetsize", "arrivalinterval", "protocol", "dstport", "srcip", "dstip", "payload", "timestamp",
        "tcp_syn", "tcp_ack", "tcp_fin", "tcp_rst", "tcp_psh", "tcp_urg", "ip_ttl", "ip_tos", "tcp_window", "direction", "label"
    };

    // Add custom features from BPF filters
    for (const auto& bpf_arg : bpf_filters) {
        auto pos = bpf_arg.find('=');
        if (pos != std::string::npos) {
            std::string feature_name = bpf_arg.substr(0, pos);
            valid_features.insert(feature_name);
        }
    }

    // Add custom features from profile
    if (!profile_file.empty()) {
        std::ifstream json_file(profile_file);
        if (json_file.is_open()) {
            try {
                json profile;
                json_file >> profile;
                if (profile.contains("bpf_filters")) {
                    for (const auto& bpf : profile["bpf_filters"]) {
                        std::string name = bpf["name"].get<std::string>();
                        valid_features.insert(name);
                    }
                }
            } catch (const json::exception& e) {
                std::cerr << "[pcap_processor] Error parsing JSON profile: " << e.what() << "\n";
            }
            json_file.close();
        } else {
            std::cerr << "[pcap_processor] Error: Could not open profile '" << profile_file << "'\n";
        }
    }

    return std::vector<std::string>(valid_features.begin(), valid_features.end());
}

void apply_suspicion_profile(packetfeatures& features, const json& profile, bool verbose) {
    if (profile.is_null() || !profile.contains("rules")) {
        if (verbose) {
            std::lock_guard<std::mutex> lock(out_mutex);
            std::cout << "[pcap_processor] No profile or rules for timestamp " << std::fixed << std::setprecision(6) << features.timestamp << "\n";
        }
        features.label = 0;
        return;
    }

    int matches = 0;
    int threshold = profile.contains("threshold") ? profile["threshold"].get<int>() : 1;
    if (verbose) {
        std::lock_guard<std::mutex> lock(out_mutex);
        std::cout << "[pcap_processor] Processing packet at " << features.timestamp << " with " << profile["rules"].size() << " rules, threshold " << threshold << "\n";
    }
    for (const auto& rule : profile["rules"]) {
        std::string feature = rule["feature"].get<std::string>();
        std::string condition = rule["condition"].get<std::string>();
        bool match = false;

        if (verbose) {
            std::lock_guard<std::mutex> lock(out_mutex);
            std::cout << "[pcap_processor] Checking rule: " << feature << " " << condition << " ";
        }
        if (feature == "packet_size") {
            float value = rule["value"].get<float>();
            if (verbose) {
                std::lock_guard<std::mutex> lock(out_mutex);
                std::cout << value << " vs " << features.packet_size << ": ";
            }
            if (condition == "equals") match = (features.packet_size == value);
            else if (condition == "greater_than") match = (features.packet_size > value);
            else if (condition == "less_than") match = (features.packet_size < value);
        } else if (feature == "protocol") {
            float value = rule["value"].get<float>();
            if (verbose) {
                std::lock_guard<std::mutex> lock(out_mutex);
                std::cout << value << " vs " << features.protocol << ": ";
            }
            if (condition == "equals") match = (features.protocol == value);
        } else if (feature == "dstport") {
            float value = rule["value"].get<float>();
            if (verbose) {
                std::lock_guard<std::mutex> lock(out_mutex);
                std::cout << value << " vs " << features.dst_p << ": ";
            }
            if (condition == "equals") match = (features.dst_p == value);
        } else if (feature == "tcp_syn") {
            int value = rule["value"].get<int>();
            if (verbose) {
                std::lock_guard<std::mutex> lock(out_mutex);
                std::cout << value << " vs " << features.tcp_syn << ": ";
            }
            if (condition == "equals") match = (features.tcp_syn == value);
        } else if (feature == "src_ip" || feature == "dst_ip") {
            std::string value = rule["value"].get<std::string>();
            if (verbose) {
                std::lock_guard<std::mutex> lock(out_mutex);
                std::cout << value << " vs " << (feature == "src_ip" ? features.src_ip : features.dst_ip) << ": ";
            }
            if (condition == "equals") match = (feature == "src_ip" ? features.src_ip == value : features.dst_ip == value);
        } else {
            for (const auto& [name, value] : features.named_payload_values) {
                if (feature == name) {
                    uint32_t rule_value = rule["value"].get<uint32_t>();
                    if (verbose) {
                        std::lock_guard<std::mutex> lock(out_mutex);
                        std::cout << rule_value << " vs " << value << ": ";
                    }
                    if (condition == "equals") match = (value == rule_value);
                    break;
                }
            }
        }
        if (verbose) {
            std::lock_guard<std::mutex> lock(out_mutex);
            std::cout << (match ? "MATCH" : "NO MATCH") << "\n";
        }
        if (match) matches++;
    }

    if (verbose) {
        std::lock_guard<std::mutex> lock(out_mutex);
        std::cout << "[pcap_processor] Matches: " << matches << " vs threshold " << threshold << "\n";
    }
    features.label = (matches >= threshold) ? 1 : 0;
    if (verbose) {
        std::lock_guard<std::mutex> lock(out_mutex);
        std::cout << "[pcap_processor] Label set to " << features.label << "\n";
    }
}

void write_packet_features(std::ofstream* out, const packetfeatures& features, const std::vector<std::string>& selected_features, bool full_payload) {
    if (!out->good()) return;
    std::ostringstream line;
    std::string payload_str;
    if (std::find(selected_features.begin(), selected_features.end(), "payload") != selected_features.end()) {
        std::ostringstream payload_ss;
        size_t max_bytes = full_payload ? features.raw_payload.size() : std::min(features.raw_payload.size(), size_t(64));
        for (size_t i = 0; i < max_bytes; ++i) {
            payload_ss << std::hex << std::setw(2) << std::setfill('0') << (int)features.raw_payload[i];
        }
        payload_str = payload_ss.str();
    }
    bool first = true;
    for (const auto& feature : selected_features) {
        if (!first) line << ",";
        if (feature == "packetsize") line << features.packet_size;
        else if (feature == "protocol") line << features.protocol;
        else if (feature == "srcip") line << features.src_ip;
        else if (feature == "dstip") line << features.dst_ip;
        else if (feature == "dstport") line << features.dst_p;
        else if (feature == "tcp_syn") line << (features.tcp_syn ? 1 : 0);
        else if (feature == "tcp_ack") line << (features.tcp_ack ? 1 : 0);
        else if (feature == "tcp_fin") line << (features.tcp_fin ? 1 : 0);
        else if (feature == "tcp_rst") line << (features.tcp_rst ? 1 : 0);
        else if (feature == "tcp_psh") line << (features.tcp_psh ? 1 : 0);
        else if (feature == "tcp_urg") line << (features.tcp_urg ? 1 : 0);
        else if (feature == "payload") line << payload_str;
        else if (feature == "timestamp") line << std::fixed << std::setprecision(6) << features.timestamp;
        else if (feature == "ip_ttl") line << (int)features.ip_ttl;
        else if (feature == "ip_tos") line << (int)features.ip_tos;
        else if (feature == "tcp_window") line << features.tcp_window;
        else if (feature == "direction") line << features.direction;
        else if (feature == "label") line << features.label;
        else {
            bool found = false;
            for (const auto& [name, value] : features.named_payload_values) {
                if (feature == name) {
                    line << value;
                    found = true;
                    break;
                }
            }
            if (!found) line << "0";
        }
        first = false;
    }
    line << "\n";
    std::lock_guard<std::mutex> lock(out_mutex);
    *out << line.str();
    out->flush();
}

void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    struct UserData {
        std::ofstream* out;
        const json* profile;
        const std::vector<std::string>* features;
        bool full_payload;
        bool verbose;
        const std::vector<std::pair<std::string, std::string>>* bpf_filters;
        const std::vector<bpf_program>* precompiled_filters;
        const std::vector<bool>* is_payload_filter;
        const std::vector<bool>* is_payload_value_filter;
        const std::vector<std::pair<int, int>>* payload_filters;
        const std::vector<Endian>* payload_endianness;
        const std::string* reference_ip;
    }* data = (UserData*)user;
    std::ofstream* out = data->out;
    const json& profile = *(data->profile);
    const std::vector<std::string>& selected_features = *(data->features);
    bool verbose = data->verbose;
    const std::vector<std::pair<std::string, std::string>>& bpf_filters = *(data->bpf_filters);
    const std::vector<bpf_program>& precompiled_filters = *(data->precompiled_filters);
    const std::vector<bool>& is_payload_filter = *(data->is_payload_filter);
    const std::vector<bool>& is_payload_value_filter = *(data->is_payload_value_filter);
    const std::vector<std::pair<int, int>>& payload_filters = *(data->payload_filters);
    const std::vector<Endian>& payload_endianness = *(data->payload_endianness);
    const std::string& reference_ip = *(data->reference_ip);

    if (!out->good()) return;

    static double last_timestamp = 0.0;
    double current_ts = header->ts.tv_sec + static_cast<double>(header->ts.tv_usec) / 1000000.0;
    double interval = (last_timestamp == 0.0) ? 0.0 : (current_ts - last_timestamp) * 1000.0;
    last_timestamp = current_ts;

    if (verbose) {
        std::lock_guard<std::mutex> lock(out_mutex);
        std::cout << "[pcap_processor] Processing packet with timestamp " << std::fixed << std::setprecision(6) << current_ts << " and length " << header->len << "\n";
    }

    if (header->len < 14) {
        if (verbose) {
            std::lock_guard<std::mutex> lock(out_mutex);
            std::cout << "[pcap_processor] Packet too short for Ethernet header\n";
        }
        return;
    }

    packetfeatures features = {};
    features.packet_size = header->len;
    features.arrival_interval = interval;
    features.timestamp = current_ts;

    const u_char* current_header = packet;
    int ethertype_offset = 12;
    uint16_t ethertype = ntohs(*(const uint16_t*)(current_header + ethertype_offset));
    int vlan_count = 0;
    while (ethertype == 0x8100 && header->len >= ethertype_offset + 4) {
        vlan_count++;
        ethertype_offset += 4;
        ethertype = ntohs(*(const uint16_t*)(current_header + ethertype_offset));
    }
    int ip_offset = 14 + (vlan_count * 4);

    if (ethertype == 0x0800) { // IPv4
        const u_char* ip_header = current_header + ip_offset;
        if (header->len < ip_offset + 20) {
            if (verbose) {
                std::lock_guard<std::mutex> lock(out_mutex);
                std::cout << "[pcap_processor] Packet too short for IPv4 header at timestamp " << std::fixed << std::setprecision(6) << current_ts << "\n";
            }
            return;
        }
        int ip_header_len = (ip_header[0] & 0x0F) * 4;
        features.protocol = ip_header[9];
        features.ip_ttl = ip_header[8];
        features.ip_tos = ip_header[1];
        char src_ip[16], dst_ip[16];
        inet_ntop(AF_INET, ip_header + 12, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, ip_header + 16, dst_ip, sizeof(dst_ip));
        features.src_ip = src_ip;
        features.dst_ip = dst_ip;

        const u_char* transport_header = ip_header + ip_header_len;
        if (features.protocol == 6 && header->len >= ip_offset + ip_header_len + 20) { // TCP
            features.tcp_offset = ip_offset + ip_header_len;
            int transport_header_len = ((transport_header[12] >> 4) * 4);
            features.dst_p = ntohs(*(const uint16_t*)(transport_header + 2));
            uint8_t tcp_flags = transport_header[13];
            if (verbose) {
                std::lock_guard<std::mutex> lock(out_mutex);
                std::cout << "[pcap_processor] TCP flags for packet at: " << std::fixed << std::setprecision(6) << current_ts << " 0x" << std::hex << (int)tcp_flags << std::dec << "\n";
            }
            features.tcp_syn = (tcp_flags & 0x02) != 0;
            features.tcp_ack = (tcp_flags & 0x10) != 0;
            features.tcp_fin = (tcp_flags & 0x01) != 0;
            features.tcp_rst = (tcp_flags & 0x04) != 0;
            features.tcp_psh = (tcp_flags & 0x08) != 0;
            features.tcp_urg = (tcp_flags & 0x20) != 0;
            features.tcp_window = ntohs(*(const uint16_t*)(transport_header + 14));
            features.payload_offset = features.tcp_offset + transport_header_len;
        } else if (features.protocol == 17 && header->len >= ip_offset + ip_header_len + 8) { // UDP
            features.dst_p = ntohs(*(const uint16_t*)(transport_header + 2));
            features.payload_offset = ip_offset + ip_header_len + 8;
        } else {
            features.payload_offset = ip_offset + ip_header_len;
        }

        size_t payload_len = (header->len > features.payload_offset) ? header->len - features.payload_offset : 0;
        const u_char* payload = packet + features.payload_offset;
        features.raw_payload.assign(payload, payload + payload_len);
    } else if (ethertype == 0x86DD) { // IPv6
        const u_char* ip6_header = current_header + ip_offset;
        if (header->len < ip_offset + 40) {
            if (verbose) {
                std::lock_guard<std::mutex> lock(out_mutex);
                std::cout << "[pcap_processor] Packet too short for IPv6 header\n";
            }
            return;
        }
        features.protocol = ip6_header[6];
        features.ip_ttl = ip6_header[7];
        features.ip_tos = (ip6_header[0] & 0x0F) << 4 | (ip6_header[1] >> 4);
        char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, ip6_header + 8, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET6, ip6_header + 24, dst_ip, sizeof(dst_ip));
        features.src_ip = src_ip;
        features.dst_ip = dst_ip;

        const u_char* next_header = ip6_header + 40;
        if (features.protocol == 6 && header->len >= ip_offset + 40 + 20) {
            features.tcp_offset = ip_offset + 40;
            int transport_header_len = ((next_header[12] >> 4) * 4);
            features.dst_p = ntohs(*(const uint16_t*)(next_header + 2));
            features.payload_offset = ip_offset + 40 + transport_header_len;
        } else if (features.protocol == 17 && header->len >= ip_offset + 40 + 8) {
            features.dst_p = ntohs(*(const uint16_t*)(next_header + 2));
            features.payload_offset = ip_offset + 40 + 8;
        } else {
            features.payload_offset = ip_offset + 40;
        }

        size_t payload_len = (header->len > features.payload_offset) ? header->len - features.payload_offset : 0;
        const u_char* payload = packet + features.payload_offset;
        features.raw_payload.assign(payload, payload + payload_len);
    } else {
        if (verbose) {
            std::lock_guard<std::mutex> lock(out_mutex);
            std::cout << "[pcap_processor] Unsupported EtherType: 0x" << std::hex << ethertype << "\n";
        }
        return;
    }

    if (!reference_ip.empty()) {
        features.direction = (features.src_ip == reference_ip || features.src_ip.find(reference_ip) != std::string::npos) ? "outbound" :
                             (features.dst_ip == reference_ip || features.dst_ip.find(reference_ip) != std::string::npos) ? "inbound" : "unknown";
    } else {
        features.direction = "unknown";
    }

    features.bpf_results.resize(bpf_filters.size());
    features.named_payload_values.resize(bpf_filters.size());

    for (size_t i = 0; i < bpf_filters.size(); ++i) {
        if (is_payload_value_filter[i]) {
            int packed_offset = payload_filters[i].first;
            int offset = packed_offset >> 8;
            int size = packed_offset & 0xFF;
            uint32_t payload_value = 0;
            const u_char* base = (bpf_filters[i].second.find("payload[") != std::string::npos) ? packet + features.payload_offset : packet + features.tcp_offset;
            if (features.protocol == 6 && base > packet && offset + size <= header->len - (base - packet)) {
                for (int j = 0; j < size; ++j) {
                    payload_value = (payload_value << 8) | base[offset + j];
                }
                if (payload_endianness[i] == Endian::Little) {
                    uint32_t reversed = 0;
                    for (int j = 0; j < size; ++j) {
                        reversed |= ((payload_value >> (j * 8)) & 0xFF) << ((size - 1 - j) * 8);
                    }
                    payload_value = reversed;
                }
            }
            features.named_payload_values[i] = {bpf_filters[i].first, payload_value};
            features.bpf_results[i] = 1;
            if (verbose) {
                std::lock_guard<std::mutex> lock(out_mutex);
                std::cout << "[pcap_processor] Extracted " << bpf_filters[i].first << " = 0x" << std::hex << payload_value << std::dec << "\n";
            }
        } else if (is_payload_filter[i]) {
            int packed_offset = payload_filters[i].first;
            int offset = packed_offset >> 8;
            int size = packed_offset & 0xFF;
            int value = payload_filters[i].second;
            uint32_t payload_value = 0;
            const u_char* base = (bpf_filters[i].second.find("payload[") != std::string::npos) ? packet + features.payload_offset : packet + features.tcp_offset;
            if (features.protocol == 6 && base > packet && offset + size <= header->len - (base - packet)) {
                for (int j = 0; j < size; ++j) {
                    payload_value = (payload_value << 8) | base[offset + j];
                }
                if (payload_endianness[i] == Endian::Little) {
                    uint32_t reversed = 0;
                    for (int j = 0; j < size; ++j) {
                        reversed |= ((payload_value >> (j * 8)) & 0xFF) << ((size - 1 - j) * 8);
                    }
                    payload_value = reversed;
                }
            }
            features.bpf_results[i] = (payload_value == (uint32_t)value) ? 1 : 0;
            features.named_payload_values[i] = {bpf_filters[i].first, 0};
        } else {
            struct bpf_program fp = precompiled_filters[i];
            features.bpf_results[i] = pcap_offline_filter(&fp, header, packet) ? 1 : 0;
            features.named_payload_values[i] = {bpf_filters[i].first, 0};
        }
    }

    bool any_filter_passed = bpf_filters.empty() || std::any_of(features.bpf_results.begin(), features.bpf_results.end(), [](int r) { return r; });
    if (any_filter_passed) {
        apply_suspicion_profile(features, profile, verbose);
        write_packet_features(out, features, selected_features, data->full_payload);
    }
}

void process_pcap(const PcapConfig& config) {
    std::ofstream out_file(config.output_file, std::ios::trunc | std::ios::binary);
    if (!out_file.is_open()) {
        std::cerr << "[pcap_processor] Error: Could not open output file '" << config.output_file << "'\n";
        return;
    }

    // Write header
    bool first = true;
    for (const auto& feature : config.features) {
        if (!first) out_file << ",";
        out_file << feature;
        first = false;
    }
    out_file << "\n";

    json profile;
    if (!config.label_file.empty()) {
        std::ifstream json_file(config.label_file);
        if (json_file.is_open()) {
            try {
                json_file >> profile;
                if (config.verbose) {
                    std::lock_guard<std::mutex> lock(out_mutex);
                    std::cout << "[pcap_processor] Loaded suspicion profile from " << config.label_file << "\n";
                }
            } catch (const json::exception& e) {
                std::cerr << "[pcap_processor] Error parsing JSON suspicion profile: " << e.what() << "\n";
            }
            json_file.close();
        } else {
            std::cerr << "[pcap_processor] Error: Could not open suspicion profile '" << config.label_file << "'\n";
        }
    }

    // Check for payload filters
    bool has_payload_filter = false;
    for (const auto& bpf_arg : config.bpf_filters) {
        if (bpf_arg.find("payload[") != std::string::npos) {
            has_payload_filter = true;
            break;
        }
    }
    if (!config.profile_file.empty()) {
        std::ifstream json_file(config.profile_file);
        if (json_file.is_open()) {
            try {
                json profile_data;
                json_file >> profile_data;
                if (profile_data.contains("bpf_filters")) {
                    for (const auto& bpf : profile_data["bpf_filters"]) {
                        std::string filter = bpf["filter"].get<std::string>();
                        if (filter.find("payload[") != std::string::npos) {
                            has_payload_filter = true;
                            break;
                        }
                    }
                }
            } catch (const json::exception& e) {
                std::cerr << "[pcap_processor] Error parsing JSON profile: " << e.what() << "\n";
            }
            json_file.close();
        }
    }

    if (has_payload_filter && config.bpf_pre_filter.empty() && !config.allow_payload_filters) {
        std::cerr << "[pcap_processor] Error: 'payload[]' filters detected without a BPF pre-filter. Aborting.\n";
        out_file.close();
        return;
    }

    // Parse BPF filters
    std::vector<std::pair<std::string, std::string>> bpf_filters;
    std::vector<std::string> raw_bpf_filters;
    std::vector<bool> is_payload_filter, is_payload_value_filter;
    std::vector<std::pair<int, int>> payload_filters;
    std::vector<Endian> payload_endianness;
    for (const auto& bpf_arg : config.bpf_filters) {
        auto pos = bpf_arg.find('=');
        if (pos == std::string::npos) {
            std::cerr << "[pcap_processor] Warning: Invalid BPF filter format: " << bpf_arg << "\n";
            continue;
        }
        std::string feature_name = bpf_arg.substr(0, pos);
        std::string filter = bpf_arg.substr(pos + 1);
        bpf_filters.emplace_back(feature_name, filter);
        raw_bpf_filters.push_back(filter);

        if (filter.find("payload[") != std::string::npos && filter.find(":") != std::string::npos) {
            is_payload_filter.push_back(false);
            is_payload_value_filter.push_back(true);
            int offset = 0, size = 0;
            sscanf(filter.c_str(), "payload[%d:%d]", &offset, &size);
            payload_filters.emplace_back((offset << 8) | size, 0);
            payload_endianness.push_back(filter.find("little") != std::string::npos ? Endian::Little : Endian::Big);
        } else if (filter.find("payload[") != std::string::npos) {
            is_payload_filter.push_back(true);
            is_payload_value_filter.push_back(false);
            int offset = 0, value = 0;
            sscanf(filter.c_str(), "payload[%d]=%i", &offset, &value);
            payload_filters.emplace_back((offset << 8) | 1, value);
            payload_endianness.push_back(filter.find("little") != std::string::npos ? Endian::Little : Endian::Big);
        } else if (filter.find("tcp[") != std::string::npos && filter.find(":") != std::string::npos) {
            is_payload_filter.push_back(false);
            is_payload_value_filter.push_back(true);
            int offset = 0, size = 0;
            sscanf(filter.c_str(), "tcp[%d:%d]", &offset, &size);
            payload_filters.emplace_back((offset << 8) | size, 0);
            payload_endianness.push_back(filter.find("little") != std::string::npos ? Endian::Little : Endian::Big);
        } else if (filter.find("tcp[") != std::string::npos) {
            is_payload_filter.push_back(true);
            is_payload_value_filter.push_back(false);
            int offset = 0, value = 0;
            sscanf(filter.c_str(), "tcp[%d]=%i", &offset, &value);
            payload_filters.emplace_back((offset << 8) | 1, value);
            payload_endianness.push_back(filter.find("little") != std::string::npos ? Endian::Little : Endian::Big);
        } else {
            is_payload_filter.push_back(false);
            is_payload_value_filter.push_back(false);
            payload_filters.emplace_back(0, 0);
            payload_endianness.push_back(Endian::Big);
        }
    }

    // Compile BPF filters
    std::vector<bpf_program> precompiled_filters;
    pcap_t* handle_template = pcap_open_dead(DLT_EN10MB, 65535);
    for (size_t i = 0; i < bpf_filters.size(); ++i) {
        if (!is_payload_filter[i] && !is_payload_value_filter[i]) {
            struct bpf_program fp;
            if (pcap_compile(handle_template, &fp, raw_bpf_filters[i].c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
                std::cerr << "[pcap_processor] Error compiling BPF filter '" << raw_bpf_filters[i] << "': " << pcap_geterr(handle_template) << "\n";
                continue;
            }
            precompiled_filters.push_back(fp);
        } else {
            struct bpf_program dummy_fp = {};
            precompiled_filters.push_back(dummy_fp);
        }
    }
    pcap_close(handle_template);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(config.input_file.c_str(), errbuf);
    if (!handle) {
        std::cerr << "[pcap_processor] Error opening " << config.input_file << ": " << errbuf << "\n";
        out_file.close();
        return;
    }

    if (!config.bpf_pre_filter.empty()) {
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, config.bpf_pre_filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "[pcap_processor] Error compiling BPF pre-filter: " << pcap_geterr(handle) << "\n";
            pcap_close(handle);
            out_file.close();
            return;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            std::cerr << "[pcap_processor] Error setting BPF pre-filter: " << pcap_geterr(handle) << "\n";
            pcap_close(handle);
            out_file.close();
            return;
        }
        pcap_freecode(&fp);
    }

    struct UserData {
        std::ofstream* out;
        const json* profile;
        const std::vector<std::string>* features;
        bool full_payload;
        bool verbose;
        const std::vector<std::pair<std::string, std::string>>* bpf_filters;
        const std::vector<bpf_program>* precompiled_filters;
        const std::vector<bool>* is_payload_filter;
        const std::vector<bool>* is_payload_value_filter;
        const std::vector<std::pair<int, int>>* payload_filters;
        const std::vector<Endian>* payload_endianness;
        const std::string* reference_ip;
    } user_data = {
        &out_file,
        &profile,
        &config.features,
        config.full_payload,
        config.verbose,
        &bpf_filters,
        &precompiled_filters,
        &is_payload_filter,
        &is_payload_value_filter,
        &payload_filters,
        &payload_endianness,
        &config.reference_ip
    };

    pcap_loop(handle, 0, packet_handler, (u_char*)&user_data);

    // Clean up compiled filters
    for (auto& fp : precompiled_filters) {
        if (fp.bf_insns) pcap_freecode(&fp);
    }
    pcap_close(handle);
    out_file.close();

    if (config.verbose) {
        std::lock_guard<std::mutex> lock(out_mutex);
        std::cout << "[pcap_processor] Processed PCAP file " << config.input_file << " to " << config.output_file << "\n";
    }
}

} // namespace pcap_processor