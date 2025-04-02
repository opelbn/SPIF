#include "logslice.hpp"
#include "cxxopts.hpp"
#include <iostream>
#include <filesystem>

namespace fs = std::filesystem;

using namespace log_processor;

Config parse_args(int argc, char* argv[], std::vector<std::string>& available_fields) {
    std::string input_dir, log_type_str;
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "-i" || std::string(argv[i]) == "--input") {
            if (i + 1 < argc) input_dir = argv[i + 1];
        }
        if (std::string(argv[i]) == "-t" || std::string(argv[i]) == "--log-type") {
            if (i + 1 < argc) log_type_str = argv[i + 1];
        }
    }
    if (input_dir.empty()) {
        std::cerr << "Error: Input directory (-i) is required.\n";
        exit(1);
    }

    Config config;
    config.input_dir = input_dir;
    config.log_type = (log_type_str == "gcp") ? LogType::GCP : 
                      (log_type_str == "netflow") ? LogType::NetFlow : LogType::Zeek;
    available_fields = (config.log_type == LogType::Zeek) ? profile_zeek(config.input_dir) :
                       (config.log_type == LogType::GCP) ? profile_gcp(config.input_dir) : 
                       profile_netflow(config.input_dir);
    if (available_fields.empty()) {
        std::cerr << "Error: No fields found in input directory " << input_dir << "\n";
        exit(1);
    }

    cxxopts::Options options(argv[0], "Log Feature Extractor");
    options.add_options()
        ("i,input", "Input directory", cxxopts::value<std::string>())
        ("o,output", "Output directory or file", cxxopts::value<std::string>())
        ("t,log-type", "Log type (zeek, gcp, or netflow)", cxxopts::value<std::string>()->default_value("zeek"))
        ("a,agg-type", "Aggregation type (pair, source, port)", cxxopts::value<std::string>()->default_value("pair"))
        ("f,profile-file", "Suspicion profile JSON file", cxxopts::value<std::string>())
        ("p,profile", "Profile dataset only")
        ("h,help", "Print usage");

    // Reserved option names
    static const std::unordered_set<std::string> reserved_options = {
        "input", "output", "log-type", "profile", "help"
    };
    
    // Map original field names to renamed options if needed
    std::unordered_map<std::string, std::string> field_to_option; // e.g., "input" -> "input_x"
    std::unordered_map<std::string, std::string> option_to_field; // e.g., "input_x" -> "input"
    for (const auto& field : available_fields) {
        std::string option_name = field;
        if (reserved_options.count(field) > 0) {
            option_name = field + "_x"; // Rename conflicting fields
        }
        field_to_option[field] = option_name;
        option_to_field[option_name] = field;
        options.add_options()(option_name, "Extract " + field);
    }

    auto result = options.parse(argc, argv);

    if (result.count("agg-type")) {
        std::string agg = result["agg-type"].as<std::string>();
        if (agg == "pair") config.agg_type = AggType::PerPair;
        else if (agg == "source") config.agg_type = AggType::PerSource;
        else if (agg == "port") config.agg_type = AggType::PerPort;
        else {
            std::cerr << "Error: Invalid agg-type '" << agg << "'\n";
            exit(1);
        }
    }
    if (result.count("profile-file")) {
        config.profile_file = result["profile-file"].as<std::string>();
    }

    if (result.count("help")) {
        std::cout << options.help() << "\nNote: Options are case-sensitive (e.g., --logName, not --logname)\n";
        exit(0);
    }

    if (result.count("profile")) {
        config.profile_only = true;
        std::cout << "Available fields (case-sensitive):\n";
        for (const auto& field : available_fields) {
            std::string option_name = field_to_option[field];
            if (field != option_name) {
                std::cout << "  --" << option_name << " (renamed from '" << field << "', --" << field << " is reserved)\n";
            } else {
                std::cout << "  --" << option_name << "\n";
            }
        }
        exit(0);
    }

    if (!result.count("output")) {
        std::cerr << "Error: Output (-o) required unless profiling.\n";
        exit(1);
    }
    config.output_path = result["output"].as<std::string>();

    for (const auto& [option_name, original_field] : option_to_field) {
        if (result.count(option_name)) {
            config.selected_features.push_back(original_field); // Store original field name
        }
    }
    if (config.selected_features.empty()) {
        config.selected_features = (config.log_type == LogType::Zeek) ? 
            std::vector<std::string>{"protocol", "service", "duration"} :
            (config.log_type == LogType::GCP) ? 
            std::vector<std::string>{"timestamp", "protoPayload.methodName", "authenticationInfo.principalEmail"} :
            std::vector<std::string>{"srcaddr", "dstaddr", "doctets"};
    }

    return config;
}

int main(int argc, char* argv[]) {
    std::vector<std::string> available_fields;
    Config config = parse_args(argc, argv, available_fields);
    
    // Load the suspicion profile
    SuspicionProfile profile = load_profile(config.profile_file);

    try {
        fs::path output_base(config.output_path);
        if (output_base.extension() == ".csv") {
            if (output_base.has_parent_path() && !output_base.parent_path().empty()) {
                fs::create_directories(output_base.parent_path());
            }
        } else {
            fs::create_directories(output_base);
        }
    } catch (const fs::filesystem_error& e) {
        std::cerr << "Error creating output directory: " << e.what() << "\n";
        return 1;
    }

    std::cout << "Processing files in " << config.input_dir << " as " 
              << (config.log_type == LogType::Zeek ? "Zeek" : config.log_type == LogType::GCP ? "GCP" : "NetFlow") << "\n";
    process_files_in_parallel(config, available_fields, profile); // Updated call with profile
    std::cout << "Processing completed\n";
    return 0;
}