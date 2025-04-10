#include "logslice.hpp"
#include "cxxopts.hpp"
#include <iostream>
#include <filesystem>
#include <algorithm>

namespace fs = std::filesystem;

using namespace log_processor;

Config parse_args(int argc, char* argv[], std::vector<std::string>& available_fields) {
    cxxopts::Options options(argv[0], "Log Feature Extractor");
    options.add_options()
        ("i,input", "Input directory", cxxopts::value<std::string>())
        ("o,output", "Output directory or file", cxxopts::value<std::string>())
        ("t,log-type", "Log type (zeek, gcp, or netflow)", cxxopts::value<std::string>()->default_value("zeek"))
        ("a,agg-type", "Aggregation type (pair, source, port)", cxxopts::value<std::string>()->default_value("pair"))
        ("f,profile-file", "Suspicion profile JSON file", cxxopts::value<std::string>())
        ("p,profile", "Profile dataset only")
        ("n,no-label", "Extract fields without labeling") // Add this
        ("h,help", "Print usage");

    static const std::unordered_set<std::string> reserved_options = {
        "input", "output", "log-type", "profile", "help", "no-label" // Add no-label
    };

    options.allow_unrecognised_options();
    cxxopts::ParseResult initial_result;
    try {
        initial_result = options.parse(argc, argv);
    } catch (const cxxopts::exceptions::no_such_option& e) {
        std::cerr << "Error during initial parsing: " << e.what() << "\n";
        exit(1);
    }

    if (initial_result.count("help")) {
        std::cout << options.help() << "\nNote: Options are case-sensitive (e.g., --logName, not --logname)\n";
        exit(0);
    }

    std::string input_dir = initial_result.count("input") ? initial_result["input"].as<std::string>() : "";
    if (input_dir.empty()) {
        std::cerr << "Error: Input directory (-i) is required.\n";
        exit(1);
    }

    Config config;
    config.input_dir = input_dir;
    std::string log_type_str = initial_result["log-type"].as<std::string>();
    config.log_type = (log_type_str == "gcp") ? LogType::GCP : 
                      (log_type_str == "netflow") ? LogType::NetFlow : LogType::Zeek;
    config.no_label = initial_result.count("no-label") > 0; // Set the flag

    try {
        available_fields = (config.log_type == LogType::Zeek) ? profile_zeek(config.input_dir) :
                           (config.log_type == LogType::GCP) ? profile_gcp(config.input_dir) : 
                           profile_netflow(config.input_dir);
    } catch (const std::exception& e) {
        std::cerr << "Error profiling input directory: " << e.what() << "\n";
        exit(1);
    }
    if (available_fields.empty()) {
        std::cerr << "Error: No fields found in input directory " << input_dir << "\n";
        exit(1);
    }

    std::unordered_map<std::string, std::string> field_to_option;
    std::unordered_map<std::string, std::string> option_to_field;
    std::unordered_set<std::string> valid_options = reserved_options;
    for (const auto& field : available_fields) {
        std::string option_name = field;
        if (reserved_options.count(field) > 0) {
            option_name = field + "_x";
        }
        field_to_option[field] = option_name;
        option_to_field[option_name] = field;
        options.add_options()(option_name, "Extract " + field);
        valid_options.insert(option_name);
    }

    cxxopts::ParseResult result;
    try {
        result = options.parse(argc, argv);
    } catch (const cxxopts::exceptions::no_such_option& e) {
        std::cerr << "Error during final parsing: " << e.what() << "\n";
        exit(1);
    }

    auto unparsed = result.unmatched();
    for (const auto& arg : unparsed) {
        if (arg.substr(0, 2) == "--" && valid_options.count(arg.substr(2)) == 0) {
            std::cerr << "Error: Unrecognized option '" << arg << "'\n";
            exit(1);
        }
    }

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

    std::vector<std::string> specified_features;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg.substr(0, 2) == "--") {
            std::string option_name = arg.substr(2);
            if (option_to_field.count(option_name)) {
                specified_features.push_back(option_to_field[option_name]);
            }
        }
    }

    for (const auto& feature : specified_features) {
        if (std::find(available_fields.begin(), available_fields.end(), feature) != available_fields.end()) {
            config.selected_features.push_back(feature);
        } else {
            std::cerr << "Warning: Field '" << feature << "' not available in dataset, ignoring.\n";
        }
    }

    if (config.selected_features.empty()) {
        if (specified_features.empty()) {
            std::cout << "No fields specified, defaulting to all available fields.\n";
        } else {
            std::cout << "No valid fields specified, defaulting to all available fields.\n";
        }
        config.selected_features = available_fields;
    }

    std::cout << "Selected features: ";
    for (const auto& feature : config.selected_features) {
        std::cout << feature << " ";
    }
    std::cout << "\n";

    return config;
}

int main(int argc, char* argv[]) {
    std::vector<std::string> available_fields;
    std::cout << "Calling parse_args...\n";
    Config config = parse_args(argc, argv, available_fields);
    std::cout << "parse_args completed.\n";
    SuspicionProfile profile = load_profile(config.profile_file);
    std::cout << "Profile loaded.\n";
    try {
        fs::path output_base(config.output_path);
        std::cout << "Creating directories for: " << output_base << "\n";
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
    process_files_in_parallel(config, available_fields, profile);
    std::cout << "Processing completed\n";
    return 0;
}