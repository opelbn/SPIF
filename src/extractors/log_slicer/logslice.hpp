#ifndef LOGSLICE_HPP
#define LOGSLICE_HPP

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <filesystem>
#include <variant>

namespace log_processor {
    enum class LogType { Zeek, GCP, NetFlow };
    enum class AggType { PerPair, PerSource, PerPort };

    struct Rule {
        std::string field;         // e.g., "doctets", "dstport"
        std::string op;            // ">", "<", "==", "in"
        std::variant<double, std::string, std::unordered_set<std::string>> value; // Numeric, string, or set
    };

    struct Config {
        std::string input_dir;
        std::string output_path;
        LogType log_type;
        AggType agg_type = AggType::PerPair;
        std::string profile_file;
        bool profile_only = false;
        std::vector<std::string> selected_features;
    };

    struct IoTConnection {
        std::unordered_map<std::string, std::string> fields;
        int label = 0;
    };

    struct AggregateStats {
        uint64_t total_bytes = 0;
        uint64_t total_packets = 0;
        std::unordered_set<std::string> dst_ports;
    };

    //define profile struct with default values
    struct SuspicionProfile {
        // Zeek-specific
        std::unordered_set<std::string> malicious_labels = {"malicious", "attack", "exploit"};
        double duration_threshold = 3600.0;
    
        // GCP-specific
        std::unordered_set<std::string> suspicious_methods = {
            "google.iam.admin.v1.CreateServiceAccount",
            "google.cloud.storage.v1.GetObject"
        };
        std::vector<std::string> non_org_domains = {"@external.com"};
        uint64_t gcp_bytes_threshold = 1000000;
    
        // NetFlow-specific
        uint64_t netflow_bytes_threshold = 10000000;
        uint64_t packets_threshold = 5000;
        size_t port_count_threshold = 10;
        std::unordered_set<unsigned int> suspicious_ports;
        std::vector<Rule> netflow_rules; // User-defined rules
    };

    std::vector<std::string> profile_zeek(const std::string& input_dir);
    std::vector<std::string> profile_gcp(const std::string& input_dir);
    std::vector<std::string> profile_netflow(const std::string& input_dir);
    SuspicionProfile load_profile(const std::string& profile_file);
    bool is_malicious_label(const std::string& label, const SuspicionProfile& profile);
    bool is_suspicious_event(const std::unordered_map<std::string, std::string>& fields, const SuspicionProfile& profile);
    bool is_suspicious_netflow(const IoTConnection& conn, const AggregateStats& stats, const SuspicionProfile& profile);
    void process_zeek(const std::string& file, const Config& config, const std::vector<std::string>& headers, const SuspicionProfile& profile);
    void process_gcp(const std::string& file, const Config& config, const std::vector<std::string>& headers, const SuspicionProfile& profile);
    void process_netflow(const std::string& file, const Config& config, const std::vector<std::string>& headers, const SuspicionProfile& profile);
    void process_files_in_parallel(const Config& config, const std::vector<std::string>& headers, const SuspicionProfile& profile);
}

#endif