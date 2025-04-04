#include <winsock2.h>
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
#include "json.hpp" // Include nlohmann/json header

namespace fs = std::filesystem;
using json = nlohmann::json;

enum class Endian { Big, Little };

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
    std::vector<int> bpf_results;
    std::vector<uint32_t> payload_values;
    bool tcp_syn = false;
    bool tcp_ack = false;
    bool tcp_fin = false;
    bool tcp_rst = false;
    bool tcp_psh = false;
    bool tcp_urg = false;
    uint8_t ip_ttl = 0;
    uint8_t ip_tos = 0;
    uint16_t tcp_window = 0;
    std::string direction;
};

struct PacketStats {
    uint64_t packet_count = 0;
    uint64_t total_bytes = 0;
    double avg_packet_size = 0.0;
};

static auto last_time = std::chrono::high_resolution_clock::now();
static double last_timestamp = 0.0;
static std::vector<std::string> selected_features;
static std::vector<std::pair<std::string, std::string>> bpf_filters;
static std::vector<std::string> raw_bpf_filters;
static std::vector<bool> is_payload_filter;
static std::vector<bool> is_payload_value_filter;
static std::vector<std::pair<int, int>> payload_filters;
static std::vector<int> payload_value_offsets;
static std::vector<std::vector<bpf_program>> precompiled_filters;
static std::vector<int> common_payload_offsets;
static std::map<int, size_t> offset_to_index;
static std::string bpf_pre_filter = "";
static size_t min_payload_len = 0;
static std::string payload_format = "hex";
static std::vector<Endian> payload_endianness;
static std::mutex out_mutex;
static std::string reference_ip = "";
static bool verbose_mode = false;
static bool stats_enabled = false;
static PacketStats global_stats;
static std::mutex stats_mutex;

std::vector<std::string> split(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(str);
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

bool ip_matches_reference(const std::string& ip) {
    if (reference_ip.empty()) return false;
    std::string ref_ip = reference_ip.find('/') != std::string::npos ? reference_ip.substr(0, reference_ip.find('/')) : reference_ip;
    return ip == ref_ip;
}

void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    std::ofstream* out = (std::ofstream*)user;
    const u_char* ip_header = packet + 14;

    if (header->len < 14 + 20) { // Minimum Ethernet + IPv4 header
        if (verbose_mode) std::cout << "Packet too short (len=" << header->len << ")\n";
        return;
    }

    int ip_header_len = (ip_header[0] & 0x0F) * 4;
    if (header->len < 14 + ip_header_len) {
        if (verbose_mode) std::cout << "Invalid IP header length\n";
        return;
    }

    const u_char* tcp_header = ip_header + ip_header_len;
    int tcp_header_len = ((tcp_header[12] >> 4) * 4);
    int payload_offset = 14 + ip_header_len + tcp_header_len;
    size_t payload_len = (header->len > payload_offset) ? header->len - payload_offset : 0;
    const u_char* payload = packet + payload_offset;

    //if (verbose_mode) {
      //  std::cout << "Processing packet with payload length " << payload_len << "\n";
    //}

    if (payload_len < min_payload_len) {
        last_timestamp = header->ts.tv_sec + header->ts.tv_usec / 1e6;
        if (verbose_mode) std::cout << "Packet skipped (payload < min_payload_len)\n";
        return;
    }

    packetfeatures features;
    features.packet_size = header->len;
    features.arrival_interval = (last_timestamp == 0.0) ? 0.0 : (header->ts.tv_sec + header->ts.tv_usec / 1e6 - last_timestamp) * 1000.0;
    last_timestamp = header->ts.tv_sec + header->ts.tv_usec / 1e6;
    features.protocol = ip_header[9];
    features.dst_p = ntohs(*(u_short*)(ip_header + 22));
    features.timestamp = last_timestamp;

    char src_ip[16], dst_ip[16];
    inet_ntop(AF_INET, ip_header + 12, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, ip_header + 16, dst_ip, sizeof(dst_ip));
    features.src_ip = src_ip;
    features.dst_ip = dst_ip;

    features.payload_offset = payload_offset;
    features.raw_payload.assign(payload, payload + payload_len);

    features.transaction_id = (payload_len >= 2) ? (payload[0] << 8) | payload[1] : 0;
    features.function_code = (payload_len >= 8) ? payload[7] : 0;

    if (features.protocol == 6 && header->len >= 14 + ip_header_len + tcp_header_len) {
        uint8_t tcp_flags = tcp_header[13];
        features.tcp_syn = (tcp_flags & 0x02) != 0;
        features.tcp_ack = (tcp_flags & 0x10) != 0;
        features.tcp_fin = (tcp_flags & 0x01) != 0;
        features.tcp_rst = (tcp_flags & 0x04) != 0;
        features.tcp_psh = (tcp_flags & 0x08) != 0;
        features.tcp_urg = (tcp_flags & 0x20) != 0;
        features.tcp_window = ntohs(*(u_short*)(tcp_header + 4));
    }

    features.ip_ttl = ip_header[8];
    features.ip_tos = ip_header[1];

    if (!reference_ip.empty()) {
        features.direction = ip_matches_reference(features.src_ip) ? "outbound" : (ip_matches_reference(features.dst_ip) ? "inbound" : "unknown");
    } else {
        features.direction = "unknown";
    }

    features.bpf_results.resize(bpf_filters.size());
    features.payload_values.resize(bpf_filters.size());

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle_template = pcap_open_dead(DLT_EN10MB, 65535);
    if (!handle_template) {
        std::cerr << "Error creating pcap handle: " << errbuf << std::endl;
        return;
    }

    size_t offset_index = 0;
    if (offset_to_index.count(features.payload_offset) > 0) {
        offset_index = offset_to_index[features.payload_offset];
    } else {
        std::cerr << "Warning: Payload offset " << features.payload_offset << " not precompiled. Adding dynamically.\n";
        common_payload_offsets.push_back(features.payload_offset);
        offset_to_index[features.payload_offset] = common_payload_offsets.size() - 1;
        offset_index = common_payload_offsets.size() - 1;
        for (size_t i = 0; i < bpf_filters.size(); ++i) {
            if (is_payload_filter[i]) {
                precompiled_filters[i].resize(common_payload_offsets.size());
                int packed_offset = payload_filters[i].first;
                int offset = packed_offset >> 8;
                int value = payload_filters[i].second;
                std::string filter = "tcp[" + std::to_string(features.payload_offset + offset) + "]=" + std::to_string(value);
                struct bpf_program fp;
                if (pcap_compile(handle_template, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
                    std::cerr << "Error compiling BPF filter '" << filter << "': " << pcap_geterr(handle_template) << std::endl;
                } else {
                    precompiled_filters[i][offset_index] = fp;
                }
            }
        }
    }

    for (size_t i = 0; i < bpf_filters.size(); ++i) {
        if (is_payload_value_filter[i]) {
            int packed_offset = payload_filters[i].first;
            int offset = packed_offset >> 8;
            int size = packed_offset & 0xFF;
            if (offset + size <= payload_len) {
                uint32_t payload_value = 0;
                for (int j = 0; j < size; ++j) {
                    payload_value = (payload_value << 8) | payload[offset + j];
                }
                if (payload_endianness[i] == Endian::Little) {
                    uint32_t reversed = 0;
                    for (int j = 0; j < size; ++j) {
                        reversed |= ((payload_value >> (j * 8)) & 0xFF) << ((size - 1 - j) * 8);
                    }
                    payload_value = reversed;
                }
                features.payload_values[i] = payload_value;
            } else {
                features.payload_values[i] = 0;
            }
            features.bpf_results[i] = 0;
        } else if (is_payload_filter[i]) {
            int packed_offset = payload_filters[i].first;
            int offset = packed_offset >> 8;
            int size = packed_offset & 0xFF;
            int value = payload_filters[i].second;
            if (offset + size <= payload_len) {
                uint32_t payload_value = 0;
                for (int j = 0; j < size; ++j) {
                    payload_value = (payload_value << 8) | payload[offset + j];
                }
                if (payload_endianness[i] == Endian::Little) {
                    uint32_t reversed = 0;
                    for (int j = 0; j < size; ++j) {
                        reversed |= ((payload_value >> (j * 8)) & 0xFF) << ((size - 1 - j) * 8);
                    }
                    payload_value = reversed;
                }
                features.bpf_results[i] = (payload_value == (uint32_t)value) ? 1 : 0;
            } else {
                features.bpf_results[i] = 0;
            }
            features.payload_values[i] = 0;
        } else {
            struct bpf_program fp = precompiled_filters[i][0];
            features.bpf_results[i] = pcap_offline_filter(&fp, header, packet) ? 1 : 0;
            features.payload_values[i] = 0;
        }
    }
    pcap_close(handle_template);

    if (stats_enabled) {
        std::lock_guard<std::mutex> stats_lock(stats_mutex);
        global_stats.packet_count++;
        global_stats.total_bytes += header->len;
        global_stats.avg_packet_size = static_cast<double>(global_stats.total_bytes) / global_stats.packet_count;
    }

    bool first = true;
    for (const auto& feature : selected_features) {
        if (!first) *out << ",";
        if (feature == "packetsize") *out << features.packet_size;
        else if (feature == "arrivalinterval") *out << features.arrival_interval;
        else if (feature == "protocol") *out << features.protocol;
        else if (feature == "dstport") *out << features.dst_p;
        else if (feature == "srcip") *out << features.src_ip;
        else if (feature == "dstip") *out << features.dst_ip;
        else if (feature == "payload") {
            if (payload_format == "hex") {
                for (size_t i = 0; i < features.raw_payload.size() && i < 64; ++i) {
                    *out << std::hex << std::setw(2) << std::setfill('0') << (int)features.raw_payload[i];
                }
            } else if (payload_format == "raw") {
                out->write((const char*)features.raw_payload.data(), features.raw_payload.size());
            }
        }
        else if (feature == "timestamp") *out << features.timestamp;
        else if (feature == "transactionid") *out << features.transaction_id;
        else if (feature == "functioncode") *out << features.function_code;
        else if (feature == "tcp_syn") *out << (features.tcp_syn ? 1 : 0);
        else if (feature == "tcp_ack") *out << (features.tcp_ack ? 1 : 0);
        else if (feature == "tcp_fin") *out << (features.tcp_fin ? 1 : 0);
        else if (feature == "tcp_rst") *out << (features.tcp_rst ? 1 : 0);
        else if (feature == "tcp_psh") *out << (features.tcp_psh ? 1 : 0);
        else if (feature == "tcp_urg") *out << (features.tcp_urg ? 1 : 0);
        else if (feature == "ip_ttl") *out << (int)features.ip_ttl;
        else if (feature == "ip_tos") *out << (int)features.ip_tos;
        else if (feature == "tcp_window") *out << features.tcp_window;
        else if (feature == "direction") *out << features.direction;
        else {
            for (size_t i = 0; i < bpf_filters.size(); ++i) {
                if (bpf_filters[i].first == feature) {
                    if (is_payload_value_filter[i]) *out << features.payload_values[i];
                    else *out << features.bpf_results[i];
                    break;
                }
            }
        }
        first = false;
    }
    *out << "\n";
    //if (!out->good()) {
      //  std::cerr << "Error writing to output stream\n";
    //}
    out->flush();
    //if (verbose_mode) {
     //   std::cout << "Wrote packet data: " << features.src_ip << "," << features.dst_ip << "\n";
    //}
}

void process_pcap(const std::string& pcap_file, std::ofstream& out) {
    if (verbose_mode) {
        std::cout << "Starting processing of " << pcap_file << "\n";
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(pcap_file.c_str(), errbuf);
    if (!handle) {
        std::cerr << "Error Opening " << pcap_file << ": " << errbuf << std::endl;
        return;
    }

    if (!bpf_pre_filter.empty()) {
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, bpf_pre_filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "Error compiling BPF pre-filter '" << bpf_pre_filter << "': " << pcap_geterr(handle) << std::endl;
            pcap_close(handle);
            return;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            std::cerr << "Error setting BPF pre-filter: " << pcap_geterr(handle) << std::endl;
            pcap_freecode(&fp);
            pcap_close(handle);
            return;
        }
        pcap_freecode(&fp);
    }

    last_timestamp = 0.0;
    if (verbose_mode) std::cout << "Entering pcap_loop for " << pcap_file << "\n";
    int result = pcap_loop(handle, 0, packet_handler, (u_char*)&out);
    if (result == -1) {
        std::cerr << "Error in pcap_loop for " << pcap_file << ": " << pcap_geterr(handle) << std::endl;
    }
    pcap_close(handle);

    if (verbose_mode) {
        std::cout << "Finished processing " << pcap_file << " with " << global_stats.packet_count << " packets processed\n";
    }
}

int main(int argc, char* argv[]) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }

    std::string input_path = "", output_file = "", profile_file = "";
    bool feature_list_specified = false, min_payload_len_specified = false, bpf_pre_filter_specified = false;
    std::set<std::string> bpf_feature_names;
    std::set<std::string> valid_features = {
        "packetsize", "arrivalinterval", "protocol", "dstport", "srcip",
        "dstip", "payload", "timestamp", "transactionid", "functioncode",
        "tcp_syn", "tcp_ack", "tcp_fin", "tcp_rst", "tcp_psh", "tcp_urg",
        "ip_ttl", "ip_tos", "tcp_window", "direction"
    };

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg[0] == '-' && arg[1] != '-' && arg != "-") {
            feature_list_specified = true;
            selected_features = split(arg.substr(1), ',');
            for (const auto& feature : selected_features) {
                if (valid_features.find(feature) == valid_features.end()) {
                    std::cerr << "Invalid feature: " << feature << "\n";
                    return 1;
                }
            }
        } else if (arg == "--in") {
            input_path = argv[++i];
        } else if (arg == "--out") {
            output_file = argv[++i];
        } else if (arg == "--bpf_pre_filter") {
            bpf_pre_filter = argv[++i];
            bpf_pre_filter_specified = true;
        } else if (arg == "--bpf") {
            std::string bpf_arg = argv[++i];
            auto pos = bpf_arg.find('=');
            if (pos == std::string::npos) {
                std::cerr << "Error: --bpf must be <feature_name>=<bpf_filter>\n";
                return 1;
            }
            std::string feature_name = bpf_arg.substr(0, pos);
            std::string filter = bpf_arg.substr(pos + 1);
            if (valid_features.count(feature_name) > 0 || bpf_feature_names.count(feature_name) > 0) {
                std::cerr << "Error: Duplicate or invalid feature name: " << feature_name << "\n";
                return 1;
            }
            bpf_feature_names.insert(feature_name);
            bpf_filters.emplace_back(feature_name, filter);
            raw_bpf_filters.push_back(filter);
            selected_features.push_back(feature_name);

            if (filter.find("payload[") == 0) {
                size_t bracket_end = filter.find(']');
                std::string offset_size_str = filter.substr(8, bracket_end - 8);
                auto colon_pos = offset_size_str.find(':');
                int offset, size = 1;
                Endian endian = Endian::Big;
                if (colon_pos != std::string::npos) {
                    std::string offset_str = offset_size_str.substr(0, colon_pos);
                    std::string size_endian = offset_size_str.substr(colon_pos + 1);
                    offset = std::stoi(offset_str);
                    auto endian_pos = size_endian.find(':');
                    if (endian_pos != std::string::npos) {
                        size = std::stoi(size_endian.substr(0, endian_pos));
                        std::string endian_str = size_endian.substr(endian_pos + 1);
                        if (endian_str == "little") endian = Endian::Little;
                    } else {
                        size = std::stoi(size_endian);
                    }
                } else {
                    offset = std::stoi(offset_size_str);
                }
                if (bracket_end + 1 < filter.length() && filter[bracket_end + 1] == '=') {
                    std::string value_str = filter.substr(bracket_end + 2);
                    int value = (value_str.find("0x") == 0) ? std::stoi(value_str, nullptr, 16) : std::stoi(value_str);
                    is_payload_filter.push_back(true);
                    is_payload_value_filter.push_back(false);
                    payload_filters.emplace_back((offset << 8) | size, value);
                    payload_value_offsets.push_back(0);
                } else {
                    is_payload_filter.push_back(false);
                    is_payload_value_filter.push_back(true);
                    payload_filters.emplace_back((offset << 8) | size, 0);
                    payload_value_offsets.push_back(offset);
                }
                payload_endianness.push_back(endian);
            } else {
                is_payload_filter.push_back(false);
                is_payload_value_filter.push_back(false);
                payload_filters.emplace_back(0, 0);
                payload_value_offsets.push_back(0);
                payload_endianness.push_back(Endian::Big);
            }
        } else if (arg == "--min_payload_len") {
            min_payload_len = std::stoul(argv[++i]);
            min_payload_len_specified = true;
        } else if (arg == "--profile") {
            profile_file = argv[++i];
        } else if (arg == "--payload_format") {
            payload_format = argv[++i];
            if (payload_format != "hex" && payload_format != "raw") {
                std::cerr << "Error: --payload_format must be 'hex' or 'raw'\n";
                return 1;
            }
        } else if (arg == "--reference_ip") {
            reference_ip = argv[++i];
        } else if (arg == "--verbose") {
            verbose_mode = true;
        } else if (arg == "--stats") {
            stats_enabled = true;
        } else {
            std::cerr << "Invalid argument: " << arg << "\n";
            return 1;
        }
    }

    if (input_path.empty() || output_file.empty()) {
        std::cerr << "Error: --in and --out are required\n";
        return 1;
    }
    if (!fs::exists(input_path)) {
        std::cerr << "Error: Input path '" << input_path << "' does not exist\n";
        return 1;
    }

    if (!profile_file.empty()) {
        std::ifstream profile_stream(profile_file);
        if (!profile_stream.is_open()) {
            std::cerr << "Error: Could not open profile file '" << profile_file << "'\n";
            return 1;
        }
        json profile;
        profile_stream >> profile;
        if (!feature_list_specified && profile.contains("features")) {
            selected_features = profile["features"].get<std::vector<std::string>>();
        }
        if (!min_payload_len_specified && profile.contains("min_payload_len")) {
            min_payload_len = profile["min_payload_len"].get<size_t>();
        }
        if (!bpf_pre_filter_specified && profile.contains("bpf_pre_filter")) {
            bpf_pre_filter = profile["bpf_pre_filter"].get<std::string>();
        }
        profile_stream.close();
    }

    if (selected_features.empty()) {
        selected_features = std::vector<std::string>(valid_features.begin(), valid_features.end());
    }

    std::cout << "\nParameters passed to the program:\n";
    std::cout << "---------------------------------\n";
    std::cout << "Input Path (--in): " << input_path << "\n";
    std::cout << "Output File (--out): " << output_file << "\n";
    if (!selected_features.empty()) {
        std::cout << "Selected Features: ";
        for (size_t i = 0; i < selected_features.size(); ++i) {
            std::cout << selected_features[i] << (i < selected_features.size() - 1 ? ", " : "\n");
        }
    }
    if (!bpf_pre_filter.empty()) {
        std::cout << "BPF Pre-Filter (--bpf_pre_filter): " << bpf_pre_filter << "\n";
    }
    if (!bpf_filters.empty()) {
        std::cout << "Custom BPF Filters (--bpf):\n";
        for (const auto& filter : bpf_filters) {
            std::cout << "  " << filter.first << " = " << filter.second << "\n";
        }
    }
    if (min_payload_len > 0) {
        std::cout << "Minimum Payload Length (--min_payload_len): " << min_payload_len << "\n";
    }
    if (!profile_file.empty()) {
        std::cout << "Profile File (--profile): " << profile_file << "\n";
    }
    std::cout << "Payload Format (--payload_format): " << payload_format << "\n";
    if (!reference_ip.empty()) {
        std::cout << "Reference IP (--reference_ip): " << reference_ip << "\n";
    }
    std::cout << "Verbose Mode (--verbose): " << (verbose_mode ? "Enabled" : "Disabled") << "\n";
    std::cout << "Statistics (--stats): " << (stats_enabled ? "Enabled" : "Disabled") << "\n";
    std::cout << "---------------------------------\n";
    std::cout << "Proceed with execution? (y/n): ";

    char response;
    std::cin >> response;
    if (std::tolower(response) != 'y') {
        std::cout << "Execution cancelled by user.\n";
        WSACleanup();
        return 0;
    }
    std::cout << "Proceeding with execution...\n";

    for (int offset = 54; offset <= 134; offset += 2) {
        common_payload_offsets.push_back(offset);
        offset_to_index[offset] = common_payload_offsets.size() - 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle_template = pcap_open_dead(DLT_EN10MB, 65535);
    if (!handle_template) {
        std::cerr << "Error creating pcap handle: " << errbuf << std::endl;
        WSACleanup();
        return 1;
    }
    precompiled_filters.resize(bpf_filters.size());
    for (size_t i = 0; i < bpf_filters.size(); ++i) {
        if (is_payload_value_filter[i]) {
            precompiled_filters[i].resize(1);
        } else if (is_payload_filter[i]) {
            precompiled_filters[i].resize(common_payload_offsets.size());
            int packed_offset = payload_filters[i].first;
            int offset = packed_offset >> 8;
            int value = payload_filters[i].second;
            for (size_t j = 0; j < common_payload_offsets.size(); ++j) {
                std::string filter = "tcp[" + std::to_string(common_payload_offsets[j] + offset) + "]=" + std::to_string(value);
                struct bpf_program fp;
                if (pcap_compile(handle_template, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
                    std::cerr << "Error compiling BPF filter '" << filter << "': " << pcap_geterr(handle_template) << std::endl;
                } else {
                    precompiled_filters[i][j] = fp;
                }
            }
        } else {
            precompiled_filters[i].resize(1);
            struct bpf_program fp;
            if (pcap_compile(handle_template, &fp, raw_bpf_filters[i].c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
                std::cerr << "Error compiling BPF filter '" << raw_bpf_filters[i] << "': " << pcap_geterr(handle_template) << std::endl;
            } else {
                precompiled_filters[i][0] = fp;
            }
        }
    }
    pcap_close(handle_template);

    std::ofstream out_file(output_file);
    if (!out_file.is_open()) {
        std::cerr << "Error: Could not open output file '" << output_file << "'\n";
        WSACleanup();
        return 1;
    }

    bool first = true;
    for (const auto& feature : selected_features) {
        if (!first) out_file << ",";
        out_file << feature;
        first = false;
    }
    out_file << "\n";
    out_file.flush();
    if (verbose_mode) std::cout << "Wrote CSV header\n";

    if (fs::is_directory(input_path)) {
        for (const auto& entry : fs::recursive_directory_iterator(input_path)) {
            if (entry.path().extension() == ".pcap") {
                process_pcap(entry.path().string(), out_file);
            }
        }
    } else if (fs::is_regular_file(input_path) && fs::path(input_path).extension() == ".pcap") {
        process_pcap(input_path, out_file);
    } else {
        std::cerr << "Error: Input path must be a directory or .pcap file\n";
        out_file.close();
        WSACleanup();
        return 1;
    }

    if (stats_enabled) {
        out_file << "\n# Statistics\n";
        out_file << "# Packet Count: " << global_stats.packet_count << "\n";
        out_file << "# Total Bytes: " << global_stats.total_bytes << "\n";
        out_file << "# Average Packet Size: " << std::fixed << std::setprecision(2) << global_stats.avg_packet_size << "\n";
        out_file.flush();
        if (verbose_mode) {
            std::cout << "Statistics:\n";
            std::cout << "  Packet Count: " << global_stats.packet_count << "\n";
            std::cout << "  Total Bytes: " << global_stats.total_bytes << "\n";
            std::cout << "  Average Packet Size: " << std::fixed << std::setprecision(2) << global_stats.avg_packet_size << " bytes\n";
        }
    }

    out_file.close();
    if (verbose_mode) std::cout << "Output file closed\n";

    for (auto& filter_set : precompiled_filters) {
        for (auto& fp : filter_set) {
            pcap_freecode(&fp);
        }
    }
    WSACleanup();
    return 0;
}