#include "logslice.hpp"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <unordered_set>
#include <future>
#include <variant>
#include "json.hpp"
using json = nlohmann::json;

namespace fs = std::filesystem;

namespace log_processor {

    std::mutex cout_mutex;

    void collect_json_fields(const json& obj, const std::string& prefix, std::vector<std::string>& fields) {
        for (auto it = obj.begin(); it != obj.end(); ++it) {
            std::string key = prefix.empty() ? it.key() : prefix + "." + it.key();
            if (it.value().is_object()) {
                collect_json_fields(it.value(), key, fields);
            } else if (!it.value().is_null()) {
                fields.push_back(key);
            }
        }
    }

    std::vector<std::string> profile_netflow(const std::string& input_dir) {
        std::vector<std::string> files;
        for (const auto& entry : fs::recursive_directory_iterator(input_dir)) {
            if (entry.path().extension() == ".csv") files.push_back(entry.path().string());
        }
        if (files.empty()) return {};
    
        std::ifstream in(files[0]);
        if (!in) {
            std::cerr << "Error: Could not read " << files[0] << "\n";
            return {};
        }
        std::string line;
        if (std::getline(in, line)) {
            std::vector<std::string> fields;
            std::stringstream ss(line);
            std::string field;
            while (std::getline(ss, field, ',')) {
                field.erase(0, field.find_first_not_of(" \t\uFEFF"));
                field.erase(field.find_last_not_of(" \t") + 1);
                if (field.substr(0, 2) == "#:") field = field.substr(2);
                if (!field.empty() && field.find(':') == std::string::npos) fields.push_back(field);
            }
            return fields;
        }
        return {};
    }

    std::vector<std::string> profile_zeek(const std::string& input_dir) {
        std::vector<std::string> files;
        for (const auto& entry : fs::recursive_directory_iterator(input_dir)) {
            std::string ext = entry.path().extension().string();
            if (ext == ".log" || ext == ".labeled") {
                files.push_back(entry.path().string());
            }
        }
        if (files.empty()) return {};
    
        std::ifstream in(files[0]);
        if (!in) {
            std::cerr << "Error: Could not open " << files[0] << "\n";
            return {};
        }
        std::string line;
        while (std::getline(in, line)) {
            if (line.substr(0, 7) == "#fields") {
                std::vector<std::string> fields;
                std::string cleaned_line = line.substr(8); // Skip "#fields\t"
                std::replace(cleaned_line.begin(), cleaned_line.end(), '\t', ' ');
                std::stringstream ss(cleaned_line);
                std::string field;
                while (ss >> field) {
                    if (!field.empty()) fields.push_back(field);
                }
                return fields;
            }
        }
        std::cerr << "Warning: No #fields line found in " << files[0] << "\n";
        return {};
    }

    std::vector<std::string> profile_gcp(const std::string& input_dir) {
        std::vector<std::string> files;
        fs::path input_path(input_dir);
    
        if (fs::is_regular_file(input_path) && input_path.extension() == ".jsonl") {
            files.push_back(input_path.string());
        } else if (fs::is_directory(input_path)) {
            for (const auto& entry : fs::recursive_directory_iterator(input_path)) {
                if (entry.path().extension() == ".jsonl") {
                    files.push_back(entry.path().string());
                }
            }
        } else {
            std::cerr << "Error: Input '" << input_dir << "' is neither a valid JSONL file nor a directory\n";
            return {};
        }
    
        if (files.empty()) {
            std::cerr << "No GCP JSONL files found in " << input_dir << "\n";
            return {};
        }
    
        std::vector<std::future<std::vector<std::string>>> futures;
        for (const auto& file : files) {
            futures.push_back(std::async(std::launch::async, [file]() {
                std::ifstream in(file);
                if (!in) {
                    std::cerr << "Error: Could not open " << file << " in profile_gcp\n";
                    return std::vector<std::string>{};
                }
                std::string line;
                while (std::getline(in, line)) {
                    if (line.empty()) continue;
                    try {
                        json entry = json::parse(line);
                        std::vector<std::string> fields;
                        collect_json_fields(entry, "", fields);
                        return fields;
                    } catch (const json::parse_error&) {
                        continue;
                    }
                }
                return std::vector<std::string>{};
            }));
        }
    
        std::unordered_set<std::string> unique_fields;
        for (auto& f : futures) {
            auto fields = f.get();
            unique_fields.insert(fields.begin(), fields.end());
        }
        if (unique_fields.empty()) {
            std::cerr << "Warning: No valid fields extracted from JSONL files in " << input_dir << "\n";
        }
        return std::vector<std::string>(unique_fields.begin(), unique_fields.end());
    }

    SuspicionProfile load_profile(const std::string& profile_file) {
        SuspicionProfile profile;

        if (profile_file.empty()) {
            return profile;
        }

        std::ifstream in(profile_file);
        if (!in) {
            std::cerr << "Warning: Could not open profile file " << profile_file << ", using defaults\n";
            return profile;
        }

        try {
            json j;
            in >> j;

            if (j.contains("zeek")) {
                auto zeek = j["zeek"];
                if (zeek.contains("malicious_labels")) profile.malicious_labels = zeek["malicious_labels"].get<std::unordered_set<std::string>>();
                if (zeek.contains("duration_threshold")) profile.duration_threshold = zeek["duration_threshold"].get<double>();
            }

            if (j.contains("gcp")) {
                auto gcp = j["gcp"];
                if (gcp.contains("suspicious_methods")) profile.suspicious_methods = gcp["suspicious_methods"].get<std::unordered_set<std::string>>();
                if (gcp.contains("non_org_domains")) profile.non_org_domains = gcp["non_org_domains"].get<std::vector<std::string>>();
                if (gcp.contains("bytes_threshold")) profile.gcp_bytes_threshold = gcp["bytes_threshold"].get<uint64_t>();
            }

            if (j.contains("netflow")) {
                auto netflow = j["netflow"];
                if (netflow.contains("bytes_threshold")) profile.netflow_bytes_threshold = netflow["bytes_threshold"].get<uint64_t>();
                if (netflow.contains("packets_threshold")) profile.packets_threshold = netflow["packets_threshold"].get<uint64_t>();
                if (netflow.contains("port_count_threshold")) profile.port_count_threshold = netflow["port_count_threshold"].get<size_t>();
                if (netflow.contains("suspicious_ports")) {
                    auto ports = netflow["suspicious_ports"].get<std::vector<unsigned int>>();
                    profile.suspicious_ports.insert(ports.begin(), ports.end());
                }
                if (netflow.contains("rules")) {
                    for (const auto& rule : netflow["rules"]) {
                        Rule r;
                        r.field = rule["field"].get<std::string>();
                        r.op = rule["op"].get<std::string>();
                        if (r.op == "in") {
                            r.value = rule["value"].get<std::unordered_set<std::string>>();
                        } else if (r.op == ">" || r.op == "<" || r.op == ">=" || r.op == "<=") {
                            r.value = rule["value"].get<double>();
                        } else if (r.op == "==" || r.op == "!=") {
                            r.value = rule["value"].get<std::string>();
                        }
                        profile.netflow_rules.push_back(r);
                    }
                }
            }
        } catch (const json::exception& e) {
            std::cerr << "Warning: Failed to parse profile file " << profile_file << ": " << e.what() << ", using defaults\n";
        }

        return profile;
    }

    bool is_malicious_label(const IoTConnection& conn, const SuspicionProfile& profile) {
        // Check if the label is in malicious_labels
        bool label_is_malicious = profile.malicious_labels.count(conn.fields.at("label")) > 0;
    
        // Check if duration exceeds threshold
        bool duration_exceeds_threshold = false;
        auto duration_it = conn.fields.find("duration");
        if (duration_it != conn.fields.end() && duration_it->second != "-") {
            try {
                double duration = std::stod(duration_it->second);
                duration_exceeds_threshold = duration > profile.duration_threshold;
            } catch (const std::exception& e) {
                std::cerr << "Warning: Could not parse duration '" << duration_it->second << "': " << e.what() << "\n";
            }
        }
    
        // Return true if either condition is met
        return label_is_malicious || duration_exceeds_threshold;
    }

    bool is_suspicious_event(const std::unordered_map<std::string, std::string>& fields, const SuspicionProfile& profile) {
        auto method_it = fields.find("protoPayload.methodName");
        if (method_it != fields.end() && profile.suspicious_methods.count(method_it->second) > 0) {
            return true;
        }

        auto email_it = fields.find("authenticationInfo.principalEmail");
        if (email_it != fields.end()) {
            const std::string& email = email_it->second;
            if (email == "-" || email.empty()) {
                return true;
            }
            for (const auto& domain : profile.non_org_domains) {
                if (email.find(domain) != std::string::npos) {
                    return true;
                }
            }
        }

        auto size_it = fields.find("protoPayload.requestSize");
        if (size_it != fields.end() && size_it->second != "-" && !size_it->second.empty()) {
            try {
                uint64_t size = std::stoull(size_it->second);
                if (size > profile.gcp_bytes_threshold) {
                    return true;
                }
            } catch (const std::exception&) {}
        }

        return false;
    }

    bool evaluate_rule(const IoTConnection& conn, const Rule& rule) {
        auto it = conn.fields.find(rule.field);
        if (it == conn.fields.end() || it->second == "-") return false;

        if (rule.op == "in") {
            auto& set = std::get<std::unordered_set<std::string>>(rule.value);
            return set.count(it->second) > 0;
        } else if (rule.op == "==" || rule.op == "!=") {
            auto& val = std::get<std::string>(rule.value);
            bool eq = it->second == val;
            return rule.op == "==" ? eq : !eq;
        } else {
            try {
                double field_val = std::stod(it->second);
                double rule_val = std::get<double>(rule.value);
                if (rule.op == ">") return field_val > rule_val;
                if (rule.op == "<") return field_val < rule_val;
                if (rule.op == ">=") return field_val >= rule_val;
                if (rule.op == "<=") return field_val <= rule_val;
            } catch (const std::exception&) {
                return false;
            }
        }
        return false;
    }

    bool is_suspicious_netflow(const IoTConnection& conn, const AggregateStats& stats, const SuspicionProfile& profile) {
        if (stats.total_bytes > profile.netflow_bytes_threshold ||
            stats.total_packets > profile.packets_threshold ||
            stats.dst_ports.size() > profile.port_count_threshold) {
            return true;
        }

        auto port_it = conn.fields.find("dstport");
        if (port_it != conn.fields.end() && port_it->second != "-") {
            try {
                unsigned int port = std::stoul(port_it->second);
                if (profile.suspicious_ports.count(port) > 0) {
                    return true;
                }
            } catch (const std::exception&) {}
        }

        for (const auto& rule : profile.netflow_rules) {
            if (evaluate_rule(conn, rule)) {
                return true;
            }
        }

        return false;
    }

    void process_gcp(const std::string& file, const Config& config, const std::vector<std::string>& headers, const SuspicionProfile& profile) {
        std::ifstream in(file);
        if (!in) {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cerr << "Error: Could not open " << file << "\n";
            return;
        }
    
        fs::path p(file);
        fs::path output_base(config.output_path);
        fs::path output_file_path = (output_base.extension() == ".csv") ? output_base : output_base / (p.stem().string() + "_features.csv");
        if (output_base.extension() != ".csv" && !fs::exists(output_base)) {
            fs::create_directories(output_base);
        }
    
        std::ofstream out(output_file_path);
        if (!out) {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cerr << "Error: Could not open " << output_file_path << "\n";
            return;
        }
    
        std::stringstream header_ss;
        for (const auto& feature : config.selected_features) header_ss << feature << ",";
        header_ss.str(header_ss.str().substr(0, header_ss.str().length() - 1));
        if (!config.no_label) header_ss << ",label";
        header_ss << "\n";
        out << header_ss.str();
    
        std::string line;
        int data_count = 0, suspicious_count = 0, normal_count = 0;
        while (std::getline(in, line)) {
            if (line.empty()) continue;
    
            json entry;
            try {
                entry = json::parse(line);
            } catch (const json::parse_error&) {
                std::lock_guard<std::mutex> lock(cout_mutex);
                std::cerr << "Warning: Malformed JSON in " << file << ": " << line << "\n";
                continue;
            }
    
            IoTConnection conn;
            json proto = entry["protoPayload"];
            json auth = entry["authenticationInfo"];
            for (const auto& feature : config.selected_features) {
                if (feature.find('.') != std::string::npos) {
                    std::stringstream ss(feature);
                    std::string key1, key2;
                    std::getline(ss, key1, '.');
                    std::getline(ss, key2);
                    if (key1 == "protoPayload" && !proto.is_null() && proto.contains(key2)) {
                        conn.fields[feature] = proto[key2].get<std::string>();
                    } else if (key1 == "authenticationInfo" && !auth.is_null() && auth.contains(key2)) {
                        conn.fields[feature] = auth[key2].get<std::string>();
                    } else {
                        conn.fields[feature] = "-";
                    }
                } else {
                    conn.fields[feature] = entry.contains(feature) ? entry[feature].get<std::string>() : "-";
                }
            }
            if (!config.no_label) {
                conn.fields["protoPayload.methodName"] = proto.contains("methodName") ? proto["methodName"].get<std::string>() : "-";
                conn.fields["authenticationInfo.principalEmail"] = auth.contains("principalEmail") ? auth["principalEmail"].get<std::string>() : "-";
                conn.fields["protoPayload.requestSize"] = proto.contains("requestSize") ? proto["requestSize"].get<std::string>() : "-";
                conn.label = is_suspicious_event(conn.fields, profile) ? 1 : 0;
                (conn.label == 1) ? suspicious_count++ : normal_count++;
            }
    
            std::stringstream row;
            for (const auto& feature : config.selected_features) row << conn.fields[feature] << ",";
            row.str(row.str().substr(0, row.str().length() - 1));
            if (!config.no_label) row << "," << conn.label;
            row << "\n";
            out << row.str();
            data_count++;
        }
    
        {
            std::lock_guard<std::mutex> lock(cout_mutex);
            if (!config.no_label) {
                std::cout << "Processed " << data_count << " lines from " << file
                          << " (Suspicious: " << suspicious_count << ", Normal: " << normal_count << ")\n";
            } else {
                std::cout << "Processed " << data_count << " lines from " << file << "\n";
            }
        }
    }

    void process_netflow(const std::string& file, const Config& config, const std::vector<std::string>& headers, const SuspicionProfile& profile) {
        std::ifstream in(file);
        if (!in) {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cerr << "Error: Could not open " << file << "\n";
            return;
        }
    
        fs::path p(file);
        fs::path output_base(config.output_path);
        fs::path output_file_path = (output_base.extension() == ".csv") ?
            output_base : output_base / (p.stem().string() + "_features.csv");
        if (output_base.extension() != ".csv" && !fs::exists(output_base)) {
            fs::create_directories(output_base);
        }
    
        std::ofstream out(output_file_path);
        if (!out) {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cerr << "Error: Could not open " << output_file_path << "\n";
            return;
        }
    
        std::stringstream header_ss;
        for (const auto& feature : config.selected_features) header_ss << feature << ",";
        header_ss.str(header_ss.str().substr(0, header_ss.str().length() - 1));
        if (!config.no_label) header_ss << ",label";
        header_ss << "\n";
        out << header_ss.str();
    
        std::map<std::string, AggregateStats> stats;
        std::string line;
        std::getline(in, line); // Skip header
    
        int data_count = 0, suspicious_count = 0, normal_count = 0;
        while (std::getline(in, line)) {
            if (line.empty()) continue;
            std::stringstream ss(line);
            std::vector<std::string> values;
            std::string token;
            while (std::getline(ss, token, ',')) values.push_back(token);
    
            IoTConnection conn;
            for (size_t i = 0; i < headers.size() && i < values.size(); ++i) {
                conn.fields[headers[i]] = values[i];
            }
    
            if (!config.no_label) {
                std::string key;
                if (config.agg_type == AggType::PerPair) {
                    key = conn.fields["srcaddr"] + "_" + conn.fields["dstaddr"];
                } else if (config.agg_type == AggType::PerSource) {
                    key = conn.fields["srcaddr"];
                } else if (config.agg_type == AggType::PerPort) {
                    key = conn.fields["dstport"];
                }
                stats[key].total_bytes += std::stoull(conn.fields["doctets"]);
                stats[key].total_packets += std::stoull(conn.fields["dpkts"]);
                stats[key].dst_ports.insert(conn.fields["dstport"]);
                conn.label = is_suspicious_netflow(conn, stats[key], profile) ? 1 : 0;
                (conn.label == 1) ? suspicious_count++ : normal_count++;
            }
    
            std::stringstream row;
            for (const auto& feature : config.selected_features) row << conn.fields[feature] << ",";
            row.str(row.str().substr(0, row.str().length() - 1));
            if (!config.no_label) row << "," << conn.label;
            row << "\n";
            out << row.str();
            data_count++;
    
            if (stats.size() > 10000) {
                stats.erase(stats.begin());
            }
        }
    
        {
            std::lock_guard<std::mutex> lock(cout_mutex);
            if (!config.no_label) {
                std::cout << "Processed " << data_count << " lines from " << file
                          << " (Suspicious: " << suspicious_count << ", Normal: " << normal_count << ")\n";
            } else {
                std::cout << "Processed " << data_count << " lines from " << file << "\n";
            }
        }
    }

    void process_zeek(const std::string& connlog_file, const Config& config, const std::vector<std::string>& headers, const SuspicionProfile& profile) {
        std::ifstream in(connlog_file);
        if (!in) {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cerr << "Error: Could not open " << connlog_file << "\n";
            return;
        }
    
        fs::path p(connlog_file);
        fs::path output_file_path = (fs::path(config.output_path).extension() == ".csv") ?
            fs::path(config.output_path) : (fs::path(config.output_path) / (p.parent_path().parent_path().filename().string() + "_" + p.stem().string() + "_features.csv"));
    
        std::ofstream out(output_file_path);
        if (!out) {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cerr << "Error: Could not open " << output_file_path << ": " << std::strerror(errno) << "\n";
            return;
        }
    
        std::stringstream header_ss;
        for (const auto& feature : config.selected_features) {
            header_ss << feature << ",";
        }
        header_ss.str(header_ss.str().substr(0, header_ss.str().length() - 1)); // Remove trailing comma
        header_ss << "\n";
        out << header_ss.str();
    
        std::string line;
        int data_count = 0, malicious_count = 0, benign_count = 0;
        while (std::getline(in, line)) {
            if (line.empty() || line[0] == '#') continue;
    
            std::vector<std::string> values;
            std::stringstream ss(line);
            std::string token;
            while (ss >> token) {
                values.push_back(token.empty() ? "-" : token);
            }
    
            if (values.size() < headers.size()) {
                values.insert(values.end(), headers.size() - values.size(), "-");
            } else if (values.size() > headers.size()) {
                values.resize(headers.size());
            }
    
            IoTConnection conn;
            for (size_t i = 0; i < headers.size(); ++i) {
                conn.fields[headers[i]] = values[i];
            }
    
            if (!config.no_label) {
                conn.label = is_malicious_label(conn, profile) ? 1 : 0;
                (conn.label == 1) ? malicious_count++ : benign_count++;
            }
    
            std::stringstream row;
            for (const auto& feature : config.selected_features) {
                row << conn.fields[feature] << ",";
            }
            row.str(row.str().substr(0, row.str().length() - 1)); // Remove trailing comma
            row << "\n";
            out << row.str();
            data_count++;
        }
    
        if (!config.no_label) {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << "Processed " << data_count << " lines from " << connlog_file
                      << " (Malicious: " << malicious_count << ", Benign: " << benign_count << ")\n";
        } else {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << "Processed " << data_count << " lines from " << connlog_file << "\n";
        }
    }

void process_files_in_parallel(const Config& config, const std::vector<std::string>& headers, const SuspicionProfile& profile) {
    std::vector<std::string> files;
    std::vector<std::string> extensions;
    if (config.log_type == LogType::Zeek) {
        extensions = {".log", ".labeled"};
    } else if (config.log_type == LogType::GCP) {
        extensions = {".jsonl"};
    } else { // NetFlow
        extensions = {".csv"};
    }
    fs::path input_path(config.input_dir);

    {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "Scanning input path: " << input_path << "\n";
    }

    if (fs::is_regular_file(input_path)) {
        std::string ext = input_path.extension().string();
        if (std::find(extensions.begin(), extensions.end(), ext) != extensions.end()) {
            files.push_back(input_path.string());
        }
    } else if (fs::is_directory(input_path)) {
        for (const auto& entry : fs::recursive_directory_iterator(input_path)) {
            std::string ext = entry.path().extension().string();
            if (std::find(extensions.begin(), extensions.end(), ext) != extensions.end()) {
                files.push_back(entry.path().string());
            }
        }
    } else {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cerr << "Error: Input '" << config.input_dir << "' is neither a valid file nor a directory for log type\n";
        return;
    }

    if (files.empty()) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cerr << "Warning: No files with extensions ";
        for (const auto& ext : extensions) std::cerr << "'" << ext << "' ";
        std::cerr << "found in " << config.input_dir << "\n";
        return;
    }

    {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "Files to process: ";
        for (const auto& file : files) std::cout << file << " ";
        std::cout << "\n";
    }

    std::vector<std::future<void>> futures;
    for (const auto& file : files) {
        if (config.log_type == LogType::Zeek) {
            futures.push_back(std::async(std::launch::async, process_zeek, file, config, headers, profile));
        } else if (config.log_type == LogType::GCP) {
            futures.push_back(std::async(std::launch::async, process_gcp, file, config, headers, profile));
        } else if (config.log_type == LogType::NetFlow) {
            futures.push_back(std::async(std::launch::async, process_netflow, file, config, headers, profile));
        }
    }

    for (auto& f : futures) {
        try {
            f.get();
        } catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cerr << "Error in thread: " << e.what() << "\n";
        }
    }
}

    
} 