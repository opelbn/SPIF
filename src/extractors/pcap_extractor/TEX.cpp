#ifdef _WIN32
#define NOMINMAX
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#endif
#include <vector>
#include <chrono>
#include <pcap.h>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <set>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <map>
#include <thread>
#include <mutex>
#include "json.hpp"
#include "cxxopts.hpp"

namespace fs = std::filesystem;
using json = nlohmann::json;

enum class Endian { Big, Little };

// Forward declaration


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

struct UserData {
    std::ofstream* out;
    const json* profile;
};

struct InterfaceInfo {
    std::string name;
    std::string description;
};

struct PacketStats { uint64_t packet_count = 0; uint64_t total_bytes = 0; double avg_packet_size = 0.0; };

static auto last_time = std::chrono::high_resolution_clock::now();
static double last_timestamp = 0.0;
static bool full_payload = false;
static std::vector<std::string> selected_features;
static std::vector<std::pair<std::string, std::string>> bpf_filters;
static std::vector<std::string> raw_bpf_filters;
static std::vector<bool> is_payload_filter, is_payload_value_filter;
static std::vector<std::pair<int, int>> payload_filters;
static std::vector<int> payload_value_offsets;
static std::vector<std::vector<bpf_program>> precompiled_filters;
static std::vector<int> common_payload_offsets = {0, 20, 40};
static std::map<int, size_t> offset_to_index;
static std::string bpf_pre_filter = "";
static size_t min_payload_len = 0;
static std::string payload_format = "hex";
static std::vector<Endian> payload_endianness;
static std::mutex out_mutex;
static std::string reference_ip = "";
static bool verbose_mode = false, stats_enabled = false;
static PacketStats global_stats;
static std::mutex stats_mutex;
//static json suspicion_profile;

void process_live(const std::string& if_name, std::ofstream& out, const json& profile, int packet_limit, int time_limit);

std::vector<std::string> split(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::istringstream tokenStream(str);
    std::string token;
    while (std::getline(tokenStream, token, delimiter)) tokens.push_back(token);
    return tokens;
}

void apply_suspicion_profile(packetfeatures& features, const json& profile) {
    if (profile.is_null() || !profile.contains("rules")) {
        if(verbose_mode) std::cout << "No profile or rules for timestamp " << features.timestamp << std::fixed << std::setprecision(6) << "\n";
        features.label = 0;
        return;
    }

    int matches = 0;
    int threshold = profile.contains("threshold") ? profile["threshold"].get<int>() : 1;
    if (verbose_mode) std::cout << "Processing packet at " << features.timestamp << " with " << profile["rules"].size() << " rules, threshold " << threshold << "\n";
    for (const auto& rule : profile["rules"]) {
        std::string feature = rule["feature"].get<std::string>();
        std::string condition = rule["condition"].get<std::string>();
        bool match = false;

        if (verbose_mode) std::cout << "Checking rule: " << feature << " " << condition << " ";
        if (feature == "packet_size") {
            float value = rule["value"].get<float>();
            if (verbose_mode) std::cout << value << " vs " << features.packet_size << ": ";
            if (condition == "equals") match = (features.packet_size == value);
            else if (condition == "greater_than") match = (features.packet_size > value);
            else if (condition == "less_than") match = (features.packet_size < value);
        } else if (feature == "protocol") {
            float value = rule["value"].get<float>();
            if (verbose_mode) std::cout << value << " vs " << features.protocol << ": ";
            if (condition == "equals") match = (features.protocol == value);
        } else if (feature == "dstport") {
            float value = rule["value"].get<float>();
            if (verbose_mode) std::cout << value << " vs " << features.dst_p << ": ";
            if (condition == "equals") match = (features.dst_p == value);
        } else if (feature == "tcp_syn") {
            int value = rule["value"].get<int>();
            if (verbose_mode) std::cout << value << " vs " << features.tcp_syn << ": ";
            if (condition == "equals") match = (features.tcp_syn == value);
        } else if (feature == "src_ip" || feature == "dst_ip") {
            std::string value = rule["value"].get<std::string>();
            if (verbose_mode) std::cout << value << " vs " << (feature == "src_ip" ? features.src_ip : features.dst_ip) << ": ";
            if (condition == "equals") match = (feature == "src_ip" ? features.src_ip == value : features.dst_ip == value);
        } else {
            for (const auto& [name, value] : features.named_payload_values) {
                if (feature == name) {
                    uint32_t rule_value = rule["value"].get<uint32_t>();
                    if (verbose_mode) std::cout << rule_value << " vs " << value << ": ";
                    if (condition == "equals") match = (value == rule_value);
                    break;
                }
            }
        }
        if (verbose_mode) std::cout << (match ? "MATCH" : "NO MATCH") << "\n";
        if (match) matches++;
    }

    if (verbose_mode) std::cout << "Matches: " << matches << " vs threshold " << threshold << "\n";
    features.label = (matches >= threshold) ? 1 : 0;
    if (verbose_mode) std::cout << "Label set to " << features.label << "\n";
}

bool ip_matches_reference(const std::string& ip) {
    if (reference_ip.empty()) return false;
    std::string ref_ip = reference_ip.find('/') != std::string::npos ? reference_ip.substr(0, reference_ip.find('/')) : reference_ip;
    return ip == ref_ip;
}



void write_basic_features(std::ofstream* out, const struct pcap_pkthdr* header, const u_char* packet, double interval, double timestamp) {
    std::ostringstream line;
    std::string payload_str;
    size_t offset = (header->len >= 14) ? 14 : 0; // Skip Ethernet header if present
    if (payload_format == "hex") {
        std::ostringstream payload_ss;
        size_t max_bytes = full_payload ? (header->len - offset) : std::min(header->len - offset, size_t(64));
        for (size_t i = offset; i < offset + max_bytes && i < header->len; ++i) {
            payload_ss << std::hex << std::setw(2) << std::setfill('0') << (int)packet[i];
        }
        payload_str = payload_ss.str();
    } else {
        payload_str.assign((const char*)(packet + offset), header->len - offset);
    }
    bool first = true;
    for (const auto& feature : selected_features) {
        if (!first) line << ",";
        if (feature == "packetsize") line << header->len;
        else if (feature == "arrivalinterval") line << interval;
        else if (feature == "timestamp") line << std::fixed << std::setprecision(6) << timestamp;
        else if (feature == "payload") line << payload_str;
        else if (feature == "srcip" || feature == "dstip") line << "N/A";
        else line << "0";
        first = false;
    }
    line << "\n";
    *out << line.str();
    out->flush();
}

void write_packet_features(std::ofstream* out, const packetfeatures& features) {
    if (!out->good()) return;
    std::ostringstream line;
    std::string payload_str;
    if (payload_format == "hex") {
        std::ostringstream payload_ss;
        size_t max_bytes = full_payload ? features.raw_payload.size() : std::min(features.raw_payload.size(), size_t(64));
        for (size_t i = 0; i < max_bytes; ++i) {
            payload_ss << std::hex << std::setw(2) << std::setfill('0') << (int)features.raw_payload[i];
        }
        payload_str = payload_ss.str();
    } else {
        payload_str.assign((const char*)features.raw_payload.data(), features.raw_payload.size());
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
        else if (feature == "payload") line << payload_str;
        else if (feature == "timestamp") line << std::fixed << std::setprecision(6) << features.timestamp;
        else if (feature == "ip_ttl") line << (int)features.ip_ttl;
        else if (feature == "ip_tos") line << (int)features.ip_tos;
        else if (feature == "tcp_window") line << features.tcp_window;
        else if (feature == "label") line << features.label;
        else {
            bool found = false;
            for (const auto& [name, value] : features.named_payload_values) {
                if (feature == name) { line << value; found = true; break; }
            }
            if (!found) line << "0";
        }
        first = false;
    }
    line << "\n";
    *out << line.str();
    out->flush();
}

void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    UserData* data = (UserData*)user;  
    std::ofstream* out = data->out;
    const json& profile = *(data->profile);

    if (!out->good()) return;

    double current_ts = header->ts.tv_sec + static_cast<double>(header->ts.tv_usec) / 1000000.0;
    double interval = (last_timestamp == 0.0) ? 0.0 : (current_ts - last_timestamp) * 1000.0;
    last_timestamp = current_ts;

    if (verbose_mode) std::cout << "Processing packet with timestamp " << std::fixed << std::setprecision(6) << current_ts << " and length " << header->len << "\n";

    if (header->len < 14) {
        if (verbose_mode) std::cout << "Packet too short for Ethernet header\n";
        write_basic_features(out, header, packet, interval, current_ts);
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
    int transport_header_len = 0; // Define here, initialize to 0

    if (ethertype == 0x0800) { // IPv4
        const u_char* ip_header = current_header + ip_offset;
        
        if (header->len < ip_offset + 20) {
            if (verbose_mode) std::cout << "Packet too short for IPv4 header at timestamp " << std::fixed << std::setprecision(6) << current_ts << "\n";
            features.payload_offset = ip_offset; // Set payload to start after Ethernet
            size_t payload_len = (header->len > features.payload_offset) ? header->len - features.payload_offset : 0;
            const u_char* payload = packet + features.payload_offset;
            features.raw_payload.assign(payload, payload + payload_len);
            features.src_ip = "N/A";
            features.dst_ip = "N/A";
            write_packet_features(out, features); // Write what we have
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

        if (features.protocol == 6) { // TCP
            if (header->len < ip_offset + ip_header_len + 20) return;
            features.tcp_offset = ip_offset + ip_header_len;
            transport_header_len = ((transport_header[12] >> 4) * 4);
            if (header->len < features.tcp_offset + transport_header_len) return;
            features.dst_p = ntohs(*(const uint16_t*)(transport_header + 2));
            uint8_t tcp_flags = transport_header[13];
            if (verbose_mode) std::cout << "TCP flags for packet at: " << std::fixed << std::setprecision(6) << current_ts << " 0x" << std::hex << (int)tcp_flags << std::dec << "\n";
            features.tcp_syn = (tcp_flags & 0x02) != 0;
            features.tcp_ack = (tcp_flags & 0x10) != 0;
            features.tcp_fin = (tcp_flags & 0x01) != 0;
            features.tcp_rst = (tcp_flags & 0x04) != 0;
            features.tcp_psh = (tcp_flags & 0x08) != 0;
            features.tcp_urg = (tcp_flags & 0x20) != 0;
            features.tcp_window = ntohs(*(const uint16_t*)(transport_header + 14));
            features.payload_offset = features.tcp_offset + transport_header_len;
        } else if (features.protocol == 17) { // UDP
            if (header->len < ip_offset + ip_header_len + 8) return;
            transport_header_len = 8;
            features.dst_p = ntohs(*(const uint16_t*)(transport_header + 2));
            features.payload_offset = ip_offset + ip_header_len + transport_header_len;
        } else if (features.protocol == 1) { // ICMP
            if (header->len < ip_offset + ip_header_len + 8) return;
            transport_header_len = 8;
            features.dst_p = 0;
            features.payload_offset = ip_offset + ip_header_len + transport_header_len;
        } else {
            transport_header_len = 0; // Non-transport protocol
            features.payload_offset = ip_offset + ip_header_len;
        }

        size_t payload_len = (header->len > features.payload_offset) ? header->len - features.payload_offset : 0;
        const u_char* payload = packet + features.payload_offset;
        features.raw_payload.assign(payload, payload + payload_len);
    } else if (ethertype == 0x86DD) { // IPv6
        const u_char* ip6_header = current_header + ip_offset;
        if (header->len < ip_offset + 40) {
            if (verbose_mode) std::cout << "Packet too short for IPv6 header\n";
            write_basic_features(out, header, packet, interval, current_ts);
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
        if (features.protocol == 58) { // ICMPv6
            if (header->len < ip_offset + 40 + 8) return;
            transport_header_len = 8;
            features.dst_p = 0;
            features.payload_offset = ip_offset + 40 + transport_header_len;
        } else if (features.protocol == 6) { // TCP
            transport_header_len = ((next_header[12] >> 4) * 4);
            features.tcp_offset = ip_offset + 40;
            if (header->len < features.tcp_offset + transport_header_len) return;
            features.dst_p = ntohs(*(const uint16_t*)(next_header + 2));
            features.payload_offset = ip_offset + 40 + transport_header_len;
        } else if (features.protocol == 17) { // UDP
            if (header->len < ip_offset + 40 + 8) return;
            transport_header_len = 8;
            features.dst_p = ntohs(*(const uint16_t*)(next_header + 2));
            features.payload_offset = ip_offset + 40 + transport_header_len;
        } else {
            transport_header_len = 0;
            features.payload_offset = ip_offset + 40;
        }

        size_t payload_len = (header->len > features.payload_offset) ? header->len - features.payload_offset : 0;
        const u_char* payload = packet + features.payload_offset;
        features.raw_payload.assign(payload, payload + payload_len);
    } else if (ethertype == 0x0806) { // ARP
        features.protocol = 0x0806;
        features.src_ip = "N/A";
        features.dst_ip = "N/A";
        features.dst_p = 0;
        features.ip_ttl = 0;
        transport_header_len = 28; // ARP header length
        features.payload_offset = ip_offset + transport_header_len;
        size_t payload_len = (header->len > features.payload_offset) ? header->len - features.payload_offset : 0;
        const u_char* payload = packet + features.payload_offset;
        features.raw_payload.assign(payload, payload + payload_len);
    } else {
        if (verbose_mode) std::cout << "Unsupported EtherType: 0x" << std::hex << ethertype << "\n";
        write_basic_features(out, header, packet, interval, current_ts);
        return;
    }

    if (!reference_ip.empty()) {
        features.direction = ip_matches_reference(features.src_ip) ? "outbound" : (ip_matches_reference(features.dst_ip) ? "inbound" : "unknown");
    } else {
        features.direction = "unknown";
    }

    features.bpf_results.resize(bpf_filters.size());
    features.named_payload_values.resize(bpf_filters.size());

    //BPF Loop
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
            if (verbose_mode) std::cout << "Extracted " << bpf_filters[i].first << " = 0x" << std::hex << payload_value << std::dec << "\n";
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
            struct bpf_program fp = precompiled_filters[i][0];
            features.bpf_results[i] = pcap_offline_filter(&fp, header, packet) ? 1 : 0;
            features.named_payload_values[i] = {bpf_filters[i].first, 0};
        }
    }

    bool any_filter_passed = bpf_filters.empty() || std::any_of(features.bpf_results.begin(), features.bpf_results.end(), [](int r) { return r; });
    if (any_filter_passed) {
        apply_suspicion_profile(features, profile); // Pass profile from main
        write_packet_features(out, features);
    }
}

void process_pcap(const std::string& pcap_file, std::ofstream& out, const json& profile) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(pcap_file.c_str(), errbuf);
    struct UserData {
        std::ofstream* out;
        const json* profile;
    } user_data = {&out, &profile};
    if (!handle) {
        std::cerr << "Error Opening " << pcap_file << ": " << errbuf << std::endl;
        return;
    }
    if (!bpf_pre_filter.empty()) {
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, bpf_pre_filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1 || pcap_setfilter(handle, &fp) == -1) {
            std::cerr << "Error with BPF pre-filter: " << pcap_geterr(handle) << std::endl;
            pcap_close(handle);
            return;
        }
        pcap_freecode(&fp);
    }
    last_timestamp = 0.0;
    pcap_loop(handle, 0, packet_handler, (u_char*)&user_data);
    pcap_close(handle);
}


// New function for live capture
void process_live(const std::string& if_name, std::ofstream& out, const json& profile, int packet_limit, int time_limit) {
    char errbuf[PCAP_ERRBUF_SIZE];
    std::cout << "Attempting to open interface: " << if_name << "\n";
    pcap_t* handle = pcap_open_live(if_name.c_str(), 65535, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Error opening interface '" << if_name << "': " << errbuf << std::endl;
        return;
    }
    std::cout << "Interface opened successfully.\n";

    if (!bpf_pre_filter.empty()) {
        struct bpf_program fp;
        std::cout << "Compiling BPF pre-filter: " << bpf_pre_filter << "\n";
        if (pcap_compile(handle, &fp, bpf_pre_filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "Error compiling BPF pre-filter: " << pcap_geterr(handle) << std::endl;
            pcap_close(handle);
            return;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            std::cerr << "Error setting BPF pre-filter: " << pcap_geterr(handle) << std::endl;
            pcap_close(handle);
            return;
        }
        pcap_freecode(&fp);
        std::cout << "BPF pre-filter applied.\n";
    }

    UserData user_data = {&out, &profile};
    last_timestamp = 0.0;

    if (time_limit > 0) {
        std::cout << "Setting time limit to " << time_limit << " seconds.\n";
        std::thread timeout_thread([handle, time_limit]() {
            std::this_thread::sleep_for(std::chrono::seconds(time_limit));
            pcap_breakloop(handle);
        });
        timeout_thread.detach();
    }

    std::cout << "Starting capture with packet limit: " << packet_limit << "\n";
    int result = pcap_loop(handle, packet_limit, packet_handler, (u_char*)&user_data);
    if (result == 0) {
        std::cout << "Capture completed (packet limit reached).\n";
    } else if (result == PCAP_ERROR_BREAK) {
        std::cout << "Capture stopped (time limit or manual break).\n";
    } else {
        std::cerr << "Capture failed: " << pcap_geterr(handle) << " (code: " << result << ")\n";
    }

    pcap_close(handle);
}

std::vector<InterfaceInfo> list_interfaces(bool show) {
    std::vector<InterfaceInfo> interfaces;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding interfaces: " << errbuf << std::endl;
        return interfaces;
    }

    if (alldevs == nullptr) {
        std::cout << "No interfaces found. Ensure you have permission or a compatible pcap library (e.g., Npcap on Windows).\n";
        return interfaces;
    }

    std::cout << "Available network interfaces:\n";
    int index = 0;
    for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
        if(show){
            std::cout << "  [" << index << "] " << dev->name;
            if (dev->description) {
                std::cout << " (" << dev->description << ")";
            }
            std::cout << "\n";
        }
        interfaces.push_back({dev->name, dev->description ? dev->description : ""});
        index++;
    }

    pcap_freealldevs(alldevs);
    return interfaces;
}


int main(int argc, char* argv[]) {
    json suspicion_profile;
    std::string label_file;

    #ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }
    std::cout << "WSAStartup completed\n" << std::flush;
    #endif

    std::string input_path, output_file;
    std::set<std::string> valid_features = {
        "packetsize", "arrivalinterval", "protocol", "dstport", "srcip", "dstip", "payload", "timestamp",
        "tcp_syn", "tcp_ack", "tcp_fin", "tcp_rst", "tcp_psh", "tcp_urg", "ip_ttl", "ip_tos", "tcp_window", "direction", "label"
    };

    cxxopts::Options options("pcap_extractor", "PCAP feature extractor");
    options.add_options()
        ("i,in", "Input PCAP file", cxxopts::value<std::string>())
        ("o,out", "Output CSV file", cxxopts::value<std::string>())
        ("f,features", "Comma-separated list of features", cxxopts::value<std::string>())
        ("b,bpf", "BPF filter with feature name (e.g., name=filter)", cxxopts::value<std::vector<std::string>>())
        ("label", "JSON suspicion profile for labeling (e.g., suspicion.json)", cxxopts::value<std::string>())
        ("bpf_pre_filter", "Pre-applied BPF filter", cxxopts::value<std::string>())
        ("min_payload_len", "Minimum payload length", cxxopts::value<size_t>())
        ("payload_format", "Payload format (hex or raw)", cxxopts::value<std::string>())
        ("reference_ip", "Reference IP for direction", cxxopts::value<std::string>())
        ("v,verbose", "Enable verbose mode")
        ("profile", "JSON profile for feature extraction (e.g., modbus.json), overrides -f/--features and -b/bpf", cxxopts::value<std::string>())
        ("full_payload", "Output full payload when payload is in selected features (otherwise default to truncated)")
        ("list_features", "List all valid features and exit")
        ("live", "Capture from live interface (index or name, e.g., 2 or eth0)", cxxopts::value<std::string>())  // New
        ("packet_limit", "Stop live capture after N packets", cxxopts::value<int>()->default_value("0"))  // 0 = unlimited
        ("time_limit", "Stop live capture after X seconds", cxxopts::value<int>()->default_value("0"))  // 0 = unlimited
        ("list_interfaces", "List available network interfaces and exit")
        ("h,help", "Print usage");

    std::cout << "Parsing arguments\n" << std::flush;
    cxxopts::ParseResult result;
    try {
        result = options.parse(argc, argv);
        std::cout << "Arguments parsed successfully\n" << std::flush;
    } catch (const cxxopts::exceptions::exception& e) {
        std::cerr << "Error parsing arguments: " << e.what() << "\n" << std::flush;
        #ifdef _WIN32
        WSACleanup();
        #endif
        return 1;
    }

    if (result.count("help")) {
        std::cout << options.help() << std::endl;
        
        #ifdef _WIN32
        WSACleanup();
        #endif
        
        return 0;
    }

    if (result.count("list_interfaces")) {
        list_interfaces(true);
        #ifdef _WIN32
        WSACleanup();
        #endif
        return 0;
    }

    if (result.count("list_features")) {
        std::cout << "Valid features:\n";
        for (const auto& feature : valid_features) {
            std::cout << "  - " << feature << "\n";
        }
        // Add custom features from --bpf if specified
        if (result.count("bpf")) {
            auto bpf_vec = result["bpf"].as<std::vector<std::string>>();
            for (const auto& bpf_arg : bpf_vec) {
                auto pos = bpf_arg.find('=');
                if (pos != std::string::npos) {
                    std::string feature_name = bpf_arg.substr(0, pos);
                    if (valid_features.insert(feature_name).second) {
                        std::cout << "  - " << feature_name << " (custom via --bpf)\n";
                    }
                }
            }
        }
        // Add custom features from profile if specified
        json profile;
        if (result.count("profile")) {
            std::string profile_file = result["profile"].as<std::string>();
            std::ifstream json_file(profile_file);
            if (!json_file.is_open()) {
                std::cerr << "Error: Could not open profile '" << profile_file << "'\n";
            } else {
                try {
                    json_file >> profile;
                    if (profile.contains("bpf_filters")) {
                        for (const auto& bpf : profile["bpf_filters"]) {
                            std::string name = bpf["name"].get<std::string>();
                            if (valid_features.insert(name).second) {
                                std::cout << "  - " << name << " (custom via profile)\n";
                            }
                        }
                    }
                } catch (const json::exception& e) {
                    std::cerr << "Error parsing JSON profile: " << e.what() << "\n";
                }
                json_file.close();
            }
        }
        #ifdef _WIN32
        WSACleanup();
        #endif
        return 0;
    }

    if (result.count("in") && result.count("live")) {
        std::cerr << "Error: --in and --live are mutually exclusive\n";
        return 1;
    }
    if (!result.count("in") && !result.count("live")) {
        std::cerr << "Error: Either --in or --live is required\n";
        return 1;
    }
    if (!result.count("out")) {
        std::cerr << "Error: --out is required\n";
        return 1;
    }

    json profile;
    if (result.count("profile") && (result.count("bpf") || result.count("b"))){
        std::cerr << "Error: If you're using a profile, include all features and bpfs in that and don't use command line args for -b/-f >>> exiting...'\n";
        #ifdef _WIN32
        WSACleanup();
        #endif
        return 1;
    }
    
    if (result.count("profile")) {
        std::string profile_file = result["profile"].as<std::string>();
        std::ifstream json_file(profile_file);
        if (!json_file.is_open()) {
            std::cerr << "Error: Could not open profile '" << profile_file << "'\n";
            #ifdef _WIN32
            WSACleanup();
            #endif
            return 1;
        }
        try {
            json_file >> profile;
            if (verbose_mode) std::cout << "Loaded profile: " << profile.dump() << "\n";
        } catch (const json::exception& e) {
            std::cerr << "Error parsing JSON profile: " << e.what() << "\n";
            #ifdef _WIN32
            WSACleanup();
            #endif
            return 1;
        }
        json_file.close();
    }


    if (!profile.is_null()) {
        if (profile.contains("features") && !result.count("features")) {
            selected_features = profile["features"].get<std::vector<std::string>>();
            if (verbose_mode) std::cout << "Profile features: ";
            for (const auto& f : selected_features) std::cout << f << " ";
            std::cout << "\n";
        }
        if (profile.contains("min_payload_len") && !result.count("min_payload_len")) {
            min_payload_len = profile["min_payload_len"].get<size_t>();
            if (verbose_mode) std::cout << "Profile min_payload_len: " << min_payload_len << "\n";
        }
        if (profile.contains("bpf_pre_filter") && !result.count("bpf_pre_filter")) {
            bpf_pre_filter = profile["bpf_pre_filter"].get<std::string>();
            if (verbose_mode) std::cout << "Profile bpf_pre_filter: " << bpf_pre_filter << "\n";
        }
        if (profile.contains("bpf_filters")) {
            for (const auto& bpf : profile["bpf_filters"]) {
                std::string name = bpf["name"].get<std::string>();
                std::string filter = bpf["filter"].get<std::string>();
                bpf_filters.emplace_back(name, filter);
                raw_bpf_filters.push_back(filter);
        
                if (filter.find("payload[") != std::string::npos && filter.find(":") != std::string::npos) {
                    is_payload_filter.push_back(false);
                    is_payload_value_filter.push_back(true);
                    int offset = 0, size = 0;
                    sscanf(filter.c_str(), "payload[%d:%d]", &offset, &size);
                    payload_filters.emplace_back((offset << 8) | size, 0);
                    payload_endianness.push_back(bpf.contains("endian") && bpf["endian"].get<std::string>() == "little" ? Endian::Little : Endian::Big);
                    valid_features.insert(name);
                    if (verbose_mode) std::cout << "Added payload value filter: " << name << "=" << filter << "\n";
                } else if (filter.find("payload[") != std::string::npos) {
                    is_payload_filter.push_back(true);
                    is_payload_value_filter.push_back(false);
                    int offset = 0, value = 0;
                    sscanf(filter.c_str(), "payload[%d]=%i", &offset, &value);
                    payload_filters.emplace_back((offset << 8) | 1, value);
                    payload_endianness.push_back(bpf.contains("endian") && bpf["endian"].get<std::string>() == "little" ? Endian::Little : Endian::Big);
                    if (verbose_mode) std::cout << "Added payload comparison filter: " << name << "=" << filter << "\n";
                } else if (filter.find("tcp[") != std::string::npos && filter.find(":") != std::string::npos) {
                    is_payload_filter.push_back(false);
                    is_payload_value_filter.push_back(true);
                    int offset = 0, size = 0;
                    sscanf(filter.c_str(), "tcp[%d:%d]", &offset, &size);
                    payload_filters.emplace_back((offset << 8) | size, 0);
                    payload_endianness.push_back(bpf.contains("endian") && bpf["endian"].get<std::string>() == "little" ? Endian::Little : Endian::Big);
                    valid_features.insert(name);
                    if (verbose_mode) std::cout << "Added TCP header value filter: " << name << "=" << filter << "\n";
                } else if (filter.find("tcp[") != std::string::npos) {
                    is_payload_filter.push_back(true);
                    is_payload_value_filter.push_back(false);
                    int offset = 0, value = 0;
                    sscanf(filter.c_str(), "tcp[%d]=%i", &offset, &value);
                    payload_filters.emplace_back((offset << 8) | 1, value);
                    payload_endianness.push_back(bpf.contains("endian") && bpf["endian"].get<std::string>() == "little" ? Endian::Little : Endian::Big);
                    if (verbose_mode) std::cout << "Added TCP header comparison filter: " << name << "=" << filter << "\n";
                } else {
                    is_payload_filter.push_back(false);
                    is_payload_value_filter.push_back(false);
                    payload_endianness.push_back(Endian::Big);
                    if (verbose_mode) std::cout << "Added standard BPF filter: " << name << "=" << filter << "\n";
                }
                valid_features.insert(name);
            }
        }
    }

    if (result.count("bpf")) {
        auto bpf_vec = result["bpf"].as<std::vector<std::string>>();
        for (const auto& bpf_arg : bpf_vec) {
            auto pos = bpf_arg.find('=');
            if (pos == std::string::npos) {
                std::cerr << "Error: --bpf must be <feature_name>=<bpf_filter>\n";
                return 1;
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
                valid_features.insert(feature_name);
                if (verbose_mode) std::cout << "Added payload value filter: " << feature_name << "=" << filter << "\n";
            } else if (filter.find("payload[") != std::string::npos) {
                is_payload_filter.push_back(true);
                is_payload_value_filter.push_back(false);
                int offset = 0, value = 0;
                sscanf(filter.c_str(), "payload[%d]=%i", &offset, &value);
                payload_filters.emplace_back((offset << 8) | 1, value);
                payload_endianness.push_back(filter.find("little") != std::string::npos ? Endian::Little : Endian::Big);
                if (verbose_mode) std::cout << "Added payload comparison filter: " << feature_name << "=" << filter << "\n";
            } else if (filter.find("tcp[") != std::string::npos && filter.find(":") != std::string::npos) {
                is_payload_filter.push_back(false);
                is_payload_value_filter.push_back(true);
                int offset = 0, size = 0;
                sscanf(filter.c_str(), "tcp[%d:%d]", &offset, &size);
                payload_filters.emplace_back((offset << 8) | size, 0);
                payload_endianness.push_back(filter.find("little") != std::string::npos ? Endian::Little : Endian::Big);
                valid_features.insert(feature_name);
                if (verbose_mode) std::cout << "Added TCP header value filter: " << feature_name << "=" << filter << "\n";
            } else if (filter.find("tcp[") != std::string::npos) {
                is_payload_filter.push_back(true);
                is_payload_value_filter.push_back(false);
                int offset = 0, value = 0;
                sscanf(filter.c_str(), "tcp[%d]=%i", &offset, &value);
                payload_filters.emplace_back((offset << 8) | 1, value);
                payload_endianness.push_back(filter.find("little") != std::string::npos ? Endian::Little : Endian::Big);
                if (verbose_mode) std::cout << "Added TCP header comparison filter: " << feature_name << "=" << filter << "\n";
            } else {
                is_payload_filter.push_back(false);
                is_payload_value_filter.push_back(false);
                payload_endianness.push_back(Endian::Big);
                if (verbose_mode) std::cout << "Added standard BPF filter: " << feature_name << "=" << filter << "\n";
            }
        }
    }

    if (result.count("verbose")) verbose_mode = true;
    if (result.count("label")) {
        label_file = result["label"].as<std::string>();
        std::ifstream json_file(label_file);
        if (!json_file.is_open()) {
            std::cerr << "Error: Could not open suspicion profile '" << label_file << "'\n";
            #ifdef _WIN32
            WSACleanup();
            #endif
            return 1;
        }
        try {
            json_file >> suspicion_profile;
        } catch (const json::exception& e) {
            std::cerr << "Error parsing JSON suspicion profile: " << e.what() << "\n";
            #ifdef _WIN32
            WSACleanup();
            #endif
            return 1;
        }
        json_file.close();
        if (verbose_mode) std::cout << "Loaded suspicion profile from " << label_file << "\n";
    }

    if (result.count("features")) {
        selected_features = split(result["features"].as<std::string>(), ',');
        for (const auto& feature : selected_features) {
            if (valid_features.find(feature) == valid_features.end()) {
                std::cerr << "Invalid feature: " << feature << "\n";
                return 1;
            }
        }
    }
    
    if (verbose_mode) std::cout << "Suspicion profile: " << suspicion_profile.dump() << "\n";
    if (result.count("in")) input_path = result["in"].as<std::string>();
    if (result.count("out")) output_file = result["out"].as<std::string>();
    if (result.count("bpf_pre_filter")) bpf_pre_filter = result["bpf_pre_filter"].as<std::string>();
    if (result.count("min_payload_len")) min_payload_len = result["min_payload_len"].as<size_t>();
    if (result.count("payload_format")) payload_format = result["payload_format"].as<std::string>();
    if (result.count("reference_ip")) reference_ip = result["reference_ip"].as<std::string>();
    
    if (result.count("full_payload")) full_payload = true;

    if ((input_path.empty() && !result.count("live")) || output_file.empty()) {
        std::cerr << "Error: Either --live or --in AND --out are required\n";
        return 1;
    }
    if (!result.count("live") && !fs::exists(input_path)) {
        std::cerr << "Error: Input path '" << input_path << "' does not exist\n";
        return 1;
    }

    bool has_payload_filter = false;
    if (result.count("bpf")) {
        auto bpf_vec = result["bpf"].as<std::vector<std::string>>();
        for (const auto& bpf_arg : bpf_vec) {
            std::string filter = bpf_arg.substr(bpf_arg.find('=') + 1);
            if (filter.find("payload[") != std::string::npos) {
                has_payload_filter = true;
                break;
            }
        }
    }
    if (profile.contains("bpf_filters")) {
        for (const auto& bpf : profile["bpf_filters"]) {
            std::string filter = bpf["filter"].get<std::string>();
            if (filter.find("payload[") != std::string::npos) {
                has_payload_filter = true;
                break;
            }
        }
    }

    if (has_payload_filter && !result.count("bpf_pre_filter") && (!profile.contains("bpf_pre_filter") || profile["bpf_pre_filter"].get<std::string>().empty())) {
        std::cout << "Warning: 'payload[]' filters detected without a BPF pre-filter. This may process unintended packets.\n";
        std::cout << "Proceed anyway? (y/n): ";
        char response;
        std::cin >> response;
        if (tolower(response) != 'y') {
            std::cout << "Aborting. Please specify a pre-filter with --bpf_pre_filter or in the profile.\n";
            #ifdef _WIN32
            WSACleanup();
            #endif
            return 1;
        }
        std::cout << "Continuing without pre-filter as requested.\n";
    }

    pcap_t* handle_template = pcap_open_dead(DLT_EN10MB, 65535);
    precompiled_filters.resize(bpf_filters.size());
    for (size_t i = 0; i < bpf_filters.size(); ++i) {
        if (!is_payload_filter[i] && !is_payload_value_filter[i]) {
            precompiled_filters[i].resize(1);
            struct bpf_program fp;
            if (pcap_compile(handle_template, &fp, raw_bpf_filters[i].c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
                std::cerr << "Error compiling BPF filter '" << raw_bpf_filters[i] << "': " << pcap_geterr(handle_template) << std::endl;
                return 1;
            }
            precompiled_filters[i][0] = fp;
        }
    }
    pcap_close(handle_template);

    for (int offset : common_payload_offsets) offset_to_index[offset] = std::distance(common_payload_offsets.begin(), std::find(common_payload_offsets.begin(), common_payload_offsets.end(), offset));
    
    std::cout << "Opening output file: " << output_file << "\n" << std::flush;
    std::ofstream out_file(output_file, std::ios::trunc | std::ios::binary);
    if (!out_file.is_open()) {
        std::cerr << "Error: Could not open output file '" << output_file << "'\n";
        return 1;
    }
    std::cout << "Output file opened\n" << std::flush;
    try {
    if (result.count("in")) {
        std::cout << "Processing PCAP file\n" << std::flush;
        std::string input_path = result["in"].as<std::string>();
        if (!fs::exists(input_path)) {
            std::cerr << "Error: Input path '" << input_path << "' does not exist\n";
            return 1;
        }
        process_pcap(input_path, out_file, suspicion_profile);
    } else if (result.count("live")) {
        std::cout << "Starting live capture\n" << std::flush;
        std::string live_arg = result["live"].as<std::string>();
        std::string if_name;
        std::vector<InterfaceInfo> interfaces = list_interfaces(false);
            if (interfaces.empty()) {
                std::cerr << "No interfaces available for live capture\n" << std::flush;
                out_file.close();
                #ifdef _WIN32
                WSACleanup();
                #endif
                return 1;
            }
            if (live_arg.find_first_not_of("0123456789") == std::string::npos) {
                int index = std::stoi(live_arg);
                if (index >= 0 && index < static_cast<int>(interfaces.size())) {
                    if_name = interfaces[index].name;
                } else {
                    std::cerr << "Error: Interface index " << index << " out of range\n" << std::flush;
                    out_file.close();
                    #ifdef _WIN32
                    WSACleanup();
                    #endif
                    return 1;
                }
            } else {
                if_name = live_arg;
            }
            std::cout << "Using interface: " << if_name << "\n" << std::flush;
            int packet_limit = result["packet_limit"].as<int>();
            int time_limit = result["time_limit"].as<int>();
            process_live(if_name, out_file, suspicion_profile, packet_limit, time_limit);
            std::cout << "Live capture completed\n" << std::flush;
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception caught: " << e.what() << "\n" << std::flush;
        out_file.close();
        #ifdef _WIN32
        WSACleanup();
        #endif
        return 1;
    }

    std::cout << "Closing output file\n" << std::flush;
    out_file.close();
    #ifdef _WIN32
    WSACleanup();
    #endif
    std::cout << "Program exiting\n" << std::flush;
    return 0;
}