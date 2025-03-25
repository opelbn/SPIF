#include <iostream>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <cxxopts.hpp>
#include <future>

namespace fs = std::filesystem;

struct IoTConnection {
    std::unordered_map<std::string, std::string> fields;
    int label = 0;
};

struct Config {
    std::vector<std::string> selected_features;
    std::string input_dir;
    std::string output_path;
    bool profile_only = false;
    bool include_label = false;
};

bool is_malicious_label(std::string_view label_str) {
    static const std::unordered_set<std::string> malicious = {
        "malicious", "partofahorizontalportscan", "ddos", "c&c", "attack"};
    std::string lower_label(label_str);
    std::transform(lower_label.begin(), lower_label.end(), lower_label.begin(), ::tolower);
    return malicious.find(lower_label) != malicious.end();
}

std::vector<std::string> parse_zeek_headers(std::ifstream& in) {
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] != '#') {
            in.seekg(0);
            return {};
        }
        if (line.find("#fields") == 0) {
            std::vector<std::string> fields;
            std::stringstream ss(line.substr(8));
            std::string field;
            while (std::getline(ss, field, '\t')) {
                field.erase(0, field.find_first_not_of(" \t"));
                field.erase(field.find_last_not_of(" \t") + 1);
                if (!field.empty()) {
                    std::stringstream sub_ss(field);
                    std::string sub_field;
                    while (std::getline(sub_ss, sub_field, ' ')) {
                        sub_field.erase(0, sub_field.find_first_not_of(" \t"));
                        sub_field.erase(sub_field.find_last_not_of(" \t") + 1);
                        if (!sub_field.empty()) {
                            fields.push_back(sub_field);
                        }
                    }
                }
            }
            in.seekg(0);
            return fields;
        }
    }
    return {};
}

std::vector<std::string> profile_dataset(const std::string& input_dir) {
    std::vector<std::string> all_fields;
    std::vector<std::string> files;

    for (const auto& entry : fs::recursive_directory_iterator(input_dir)) {
        if (entry.path().extension() == ".labeled" && entry.path().stem().extension() == ".log") {
            files.push_back(entry.path().string());
        }
    }

    if (files.empty()) {
        std::cerr << "No Zeek log files found in " << input_dir << "\n";
        return all_fields;
    }

    std::vector<std::future<std::vector<std::string>>> futures;
    for (const auto& file : files) {
        futures.push_back(std::async(std::launch::async, [file]() {
            std::ifstream in(file);
            return parse_zeek_headers(in);
        }));
    }

    for (auto& f : futures) {
        auto fields = f.get();
        if (!fields.empty()) {
            all_fields = fields;
            break;
        }
    }

    return all_fields;
}

void process_file(const std::string& connlog_file, const std::string& output_path,
                 const std::vector<std::string>& selected_features,
                 const std::vector<std::string>& header_fields,
                 bool include_label) {
    std::ifstream in(connlog_file);
    if (!in) {
        std::cerr << "Error: Could not open input file " << connlog_file << "\n";
        return;
    }

    fs::path p(connlog_file);
    fs::path output_file_path;

    // Check if output_path is a file (ends with .csv) or a directory
    fs::path output_path_fs(output_path);
    if (output_path_fs.extension() == ".csv") {
        output_file_path = output_path_fs;
    } else {
        std::string generated_filename = p.parent_path().parent_path().filename().string() + "_" +
                                        p.stem().string() + "_features.csv";
        output_file_path = fs::path(output_path) / generated_filename;
    }

    // Debug: Log the absolute path we're trying to write to
    std::cout << "Attempting to write to: " << fs::absolute(output_file_path) << "\n";

    std::ofstream out(output_file_path);
    if (!out) {
        std::cerr << "Error: Could not open output file " << output_file_path << ": " << std::strerror(errno) << "\n";
        in.close();
        return;
    }

    std::stringstream header_ss;
    for (const auto& feature : selected_features) {
        if (feature != "label") {
            header_ss << feature << ",";
        }
    }
    header_ss << "label\n";
    out << header_ss.str();

    std::string line;
    int data_count = 0, malicious_count = 0, benign_count = 0;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;

        std::stringstream ss(line);
        std::vector<std::string> tab_values;
        std::string token;
        while (std::getline(ss, token, '\t')) {
            token.erase(0, token.find_first_not_of(" \t"));
            token.erase(token.find_last_not_of(" \t") + 1);
            tab_values.push_back(token.empty() ? "-" : token);
        }

        std::vector<std::string> values;
        for (size_t i = 0; i < 20 && i < tab_values.size(); ++i) {
            values.push_back(tab_values[i]);
        }
        if (tab_values.size() >= 21) {
            std::stringstream sub_ss(tab_values[20]);
            std::vector<std::string> sub_values;
            std::string sub_token;
            while (std::getline(sub_ss, sub_token, ' ')) {
                sub_token.erase(0, sub_token.find_first_not_of(" \t"));
                sub_token.erase(sub_token.find_last_not_of(" \t") + 1);
                if (!sub_token.empty()) {
                    sub_values.push_back(sub_token);
                }
            }
            if (sub_values.size() >= 1) values.push_back(sub_values[0]); // tunnel_parents
            else values.push_back("-");
            if (sub_values.size() >= 2) values.push_back(sub_values[1]); // label
            else values.push_back("-");
            if (sub_values.size() >= 3) values.push_back(sub_values[2]); // detailed-label
            else values.push_back("-");
        } else {
            values.push_back("-"); // tunnel_parents
            values.push_back("-"); // label
            values.push_back("-"); // detailed-label
        }

        if (values.size() != header_fields.size()) {
            std::cerr << "Warning: Malformed line in " << connlog_file << ": " << line << "\n";
            std::cerr << "Parsed " << values.size() << " values, expected " << header_fields.size() << "\n";
            continue;
        }

        IoTConnection conn;
        for (size_t i = 0; i < header_fields.size(); ++i) {
            conn.fields[header_fields[i]] = values[i];
        }

        std::string label_str = conn.fields["label"];
        conn.label = is_malicious_label(label_str) ? 1 : 0;
        (conn.label == 1) ? malicious_count++ : benign_count++;

        std::stringstream row;
        for (const auto& feature : selected_features) {
            if (feature != "label") {
                row << conn.fields[feature] << ",";
            }
        }
        row << conn.label << "\n";
        out << row.str();

        data_count++;
    }

    std::cout << "Processed " << data_count << " lines from " << connlog_file
              << " (Malicious: " << malicious_count << ", Benign: " << benign_count << ")\n";

    in.close();
    out.close();
}

void process_files_in_parallel(const Config& config, const std::vector<std::string>& header_fields) {
    std::vector<std::string> files;
    for (const auto& entry : fs::recursive_directory_iterator(config.input_dir)) {
        if (entry.path().extension() == ".labeled" && entry.path().stem().extension() == ".log") {
            files.push_back(entry.path().string());
        }
    }

    std::vector<std::future<void>> futures;
    for (const auto& file : files) {
        futures.push_back(std::async(std::launch::async, process_file, file, config.output_path,
                                     config.selected_features, header_fields, config.include_label));
    }

    for (auto& f : futures) {
        f.wait();
    }
}

Config parse_args(int argc, char* argv[], std::vector<std::string>& available_fields) {
    std::string input_dir;
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "-i" || std::string(argv[i]) == "--input") {
            if (i + 1 < argc) {
                input_dir = argv[i + 1];
                break;
            }
        }
    }
    if (input_dir.empty()) {
        std::cerr << "Error: Input directory (-i) is required.\n";
        exit(1);
    }

    available_fields = profile_dataset(input_dir);
    if (available_fields.empty()) {
        std::cerr << "No valid Zeek headers found in dataset.\n";
        exit(1);
    }

    cxxopts::Options options(argv[0], "Zeek Log Feature Extractor");
    options.add_options()
        ("i,input", "Input directory", cxxopts::value<std::string>())
        ("o,output", "Output directory or file", cxxopts::value<std::string>())
        ("p,profile", "Profile dataset and display headers only")
        ("h,help", "Print usage");

    for (const auto& field : available_fields) {
        if (field.find(' ') == std::string::npos) {
            options.add_options()(field, "Extract " + field);
        } else {
            std::cerr << "Warning: Skipping invalid field name '" << field << "'\n";
        }
    }

    auto result = options.parse(argc, argv);

    if (result.count("help")) {
        std::cout << options.help() << std::endl;
        exit(0);
    }

    Config config;
    config.input_dir = result["input"].as<std::string>();
    config.profile_only = result.count("profile") > 0;

    if (config.profile_only) {
        std::cout << "Available field headers in dataset:\n";
        for (const auto& field : available_fields) {
            std::cout << "  --" << field << "\n";
        }
        std::cout << "Use these fields as flags (e.g., --ts --proto) to extract features.\n";
        exit(0);
    }

    if (!result.count("output")) {
        std::cerr << "Error: Output directory or file (-o) is required unless using --profile.\n";
        std::cout << options.help() << std::endl;
        exit(1);
    }
    config.output_path = result["output"].as<std::string>();

    for (const auto& field : available_fields) {
        if (result.count(field)) {
            config.selected_features.push_back(field);
        }
    }

    config.include_label = std::find(config.selected_features.begin(), config.selected_features.end(), "label") != config.selected_features.end();

    if (config.selected_features.empty()) {
        config.selected_features = {"protocol", "service", "duration", "orig_bytes", "resp_bytes"};
        std::cout << "No features specified. Using defaults: ";
        for (const auto& f : config.selected_features) std::cout << f << " ";
        std::cout << "\n";
    }

    for (const auto& feature : config.selected_features) {
        if (std::find(available_fields.begin(), available_fields.end(), feature) == available_fields.end()) {
            std::cerr << "Warning: Feature '" << feature << "' not found in dataset. Ignoring.\n";
        }
    }

    return config;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " -i <input_dir> [-o <output_dir_or_file>] [--profile] [--feature1] [--feature2] ...\n";
        return 1;
    }

    std::vector<std::string> available_fields;
    Config config = parse_args(argc, argv, available_fields);

    fs::path output_path_fs(config.output_path);
    if (output_path_fs.extension() != ".csv") {
        fs::create_directory(config.output_path);
    } else {
        if (output_path_fs.has_parent_path()) {
            try {
                fs::create_directories(output_path_fs.parent_path());
            } catch (const fs::filesystem_error& e) {
                std::cerr << "Error: Could not create parent directories for " << output_path_fs << ": " << e.what() << "\n";
                return 1;
            }
        }
    }

    std::cout << "Processing files in " << fs::absolute(config.input_dir) << "\n";
    std::cout << "Selected features: ";
    for (const auto& f : config.selected_features) std::cout << f << " ";
    std::cout << "\n";

    process_files_in_parallel(config, available_fields);
    std::cout << "Processing completed\n";
    return 0;
}