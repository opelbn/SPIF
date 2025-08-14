#include "ml_pipeline.hpp"
#include "pcap_processor.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include "logslice.hpp"
#include "time_series_preprocessor.hpp"
#include "json.hpp"

using json = nlohmann::json;

namespace ml_pipeline {
//you should be registering dynamically according to components listed in the startup manifest
MLPipeline::MLPipeline() {
    config_ = PipelineConfig(); // Initialize config_
    // Register Zeek extractor
    register_component({
        "zeek_extractor",
        ComponentType::Extractor,
        {"log_dir"},
        {"timestamp", "srcip", "dstip", "dstport", "duration", "label"},
        [](const std::map<std::string, std::string>& params) {
            log_processor::Config config;
            config.input_dir = params.at("input_dir");
            config.output_path = params.at("output_path");
            config.log_type = log_processor::LogType::Zeek;
            if (params.find("features") != params.end()) {
                std::stringstream ss(params.at("features"));
                std::string feature;
                while (std::getline(ss, feature, ',')) {
                    config.selected_features.push_back(feature);
                }
            } else {
                config.selected_features = {"ts", "id.orig_h", "id.resp_h", "id.resp_p", "duration", "label"};
            }
            auto headers = log_processor::profile_zeek(config.input_dir);
            auto profile = log_processor::load_profile(params.find("profile_file") != params.end() ? params.at("profile_file") : "");
            log_processor::process_files_in_parallel(config, headers, profile);
        }
    });

    // Register PCAP extractor
    register_component({
        "pcap_extractor",
        ComponentType::Extractor,
        {"pcap_file"},
        {"packetsize", "arrivalinterval", "protocol", "dstport", "srcip", "dstip", "payload", "timestamp", "tcp_syn", "tcp_ack", "ip_ttl", "ip_tos", "tcp_window", "direction", "label", "custom_bpf"},
        [](const std::map<std::string, std::string>& params) {
            pcap_processor::PcapConfig config;
            config.input_file = params.at("input_file");
            config.output_file = params.at("output_path");
            config.verbose = params.find("verbose") != params.end() && params.at("verbose") == "true";
            config.full_payload = params.find("full_payload") != params.end() && params.at("full_payload") == "true";
            config.allow_payload_filters = params.find("allow_payload_filters") != params.end() && params.at("allow_payload_filters") == "true";
            if (params.find("bpf_pre_filter") != params.end()) {
                config.bpf_pre_filter = params.at("bpf_pre_filter");
            }
            if (params.find("label_file") != params.end()) {
                config.label_file = params.at("label_file");
            }
            if (params.find("profile_file") != params.end()) {
                config.profile_file = params.at("profile_file");
            }
            if (params.find("reference_ip") != params.end()) {
                config.reference_ip = params.at("reference_ip");
            }
            if (params.find("bpf_filters") != params.end()) {
                std::stringstream ss(params.at("bpf_filters"));
                std::string filter;
                while (std::getline(ss, filter, ';')) {
                    config.bpf_filters.push_back(filter);
                }
            }
            if (params.find("features") != params.end()) {
                std::stringstream ss(params.at("features"));
                std::string feature;
                while (std::getline(ss, feature, ',')) {
                    config.features.push_back(feature);
                }
            }
            pcap_processor::process_pcap(config);
        }
    });

    // Register time-series preprocessor
    register_component({
        "time_series_preprocessor",
        ComponentType::Preprocessor,
        {"timestamp", "numeric_features"},
        {"timestamp", "normalized_features", "label"},
        [](const std::map<std::string, std::string>& params) {
            time_series_preprocessor::TimeSeriesConfig config;
            config.input_file = params.at("input_file");
            config.output_file = params.at("output_file");
            config.window_size_seconds = std::stod(params.at("window_size"));
            config.normalize = params.find("normalize") != params.end() && params.at("normalize") == "true";
            config.timestamp_column = "timestamp";
            config.label_column = "label";
            std::stringstream ss(params.at("features"));
            std::string feature;
            while (std::getline(ss, feature, ',')) {
                config.features.push_back(feature);
            }
            time_series_preprocessor::TimeSeriesPreprocessor preprocessor(config);
            preprocessor.preprocess();
        }
    });

    // Register Isolation Forest model (placeholder)
    register_component({
        "isolation_forest",
        ComponentType::Model,
        {"timestamp", "normalized_features"},
        {"anomaly_scores"},
        [](const std::map<std::string, std::string>& params) {
            std::cout << "[isolation_forest] Training Isolation Forest model (placeholder)\n";
            // Implement model training here
        }
    });
}

void MLPipeline::register_component(const Component& component) {
    components_[component.name] = component;
}

void MLPipeline::run_pipeline(const PipelineConfig& config) {
    std::string error;
    if (!validate_pipeline(config, error)) {
        std::cerr << "Pipeline validation failed: " << error << "\n";
        return;
    }

    std::map<std::string, std::string> params = config.params;
    params["input_dir"] = config.input_path;
    params["input_file"] = config.input_path;
    params["output_path"] = config.output_path;

    for (const auto& comp_name : config.components) {
        std::cout << "Executing component: " << comp_name << "\n";
        execute_component(comp_name, params);
        // Update params for next component
        params["input_file"] = params["output_path"];
        params["output_path"] = params["output_path"] + "_" + comp_name + ".csv";
    }
}

void MLPipeline::execute_component(const std::string& component_name, const std::map<std::string, std::string>& params) {
    if (components_.count(component_name)) {
        components_[component_name].execute(params);
    } else {
        std::cerr << "Error: Component " << component_name << " not found\n";
    }
}

bool MLPipeline::validate_pipeline(const PipelineConfig& config, std::string& error) const {
    std::vector<std::string> available_outputs;
    if (config.components.empty()) {
        error = "No components specified";
        return false;
    }

    // Initialize available outputs based on first component's inputs
    if (components_.count(config.components[0])) {
        const auto& first_comp = components_.at(config.components[0]);
        if (first_comp.type != ComponentType::Extractor) {
            error = "First component must be an extractor";
            return false;
        }
        available_outputs = get_available_features(config.input_path, config.params.at("log_type"));
    } else {
        error = "First component not found";
        return false;
    }

    for (size_t i = 0; i < config.components.size(); ++i) {
        const auto& comp_name = config.components[i];
        if (!components_.count(comp_name)) {
            error = "Component " + comp_name + " not found";
            return false;
        }

        const auto& comp = components_.at(comp_name);
        // Check if required inputs are available
        for (const auto& input : comp.inputs) {
            if (input == "log_dir" || input == "pcap_file" || input == "input_file") continue;
            if (input == "custom_bpf") continue; // Custom BPF features are optional
            if (std::find(available_outputs.begin(), available_outputs.end(), input) == available_outputs.end()) {
                error = "Component " + comp_name + " requires input " + input + " which is not available";
                return false;
            }
        }

        // Update available outputs
        available_outputs.insert(available_outputs.end(), comp.outputs.begin(), comp.outputs.end());
    }

    return true;
}

void MLPipeline::save_config(const std::string& file_path) const {
    try {
        json j;
        j["input_path"] = config_.input_path;
        j["output_path"] = config_.output_path;
        j["components"] = config_.components;
        j["params"] = config_.params;

        std::ofstream out(file_path);
        if (!out.is_open()) {
            std::cerr << "Error: Could not open file '" << file_path << "' for writing\n";
            return;
        }
        out << j.dump(4); // Pretty-print with 4-space indentation
        out.close();
        std::cout << "Configuration saved to: " << file_path << "\n";
    } catch (const std::exception& e) {
        std::cerr << "Error saving configuration: " << e.what() << "\n";
    }
}

void MLPipeline::load_config(const std::string& file_path) {
    try {
        std::ifstream in(file_path);
        if (!in.is_open()) {
            std::cerr << "Error: Could not open file '" << file_path << "' for reading\n";
            return;
        }
        json j;
        in >> j;
        in.close();

        config_ = PipelineConfig(); // Reset config_
        if (j.contains("input_path")) {
            config_.input_path = j["input_path"].get<std::string>();
        }
        if (j.contains("output_path")) {
            config_.output_path = j["output_path"].get<std::string>();
        }
        if (j.contains("components")) {
            config_.components = j["components"].get<std::vector<std::string>>();
        }
        if (j.contains("params")) {
            config_.params = j["params"].get<std::map<std::string, std::string>>();
        }

        std::cout << "Configuration loaded from: " << file_path << "\n";
    } catch (const json::exception& e) {
        std::cerr << "Error parsing JSON configuration: " << e.what() << "\n";
    } catch (const std::exception& e) {
        std::cerr << "Error loading configuration: " << e.what() << "\n";
    }
}

std::vector<std::string> MLPipeline::get_available_features(const std::string& input_path, const std::string& log_type) const {
    std::vector<std::string> bpf_filters;
    std::string profile_file;
    if (log_type == "pcap") {
        if (config_.params.find("bpf_filters") != config_.params.end()) {
            std::stringstream ss(config_.params.at("bpf_filters"));
            std::string filter;
            while (std::getline(ss, filter, ';')) {
                bpf_filters.push_back(filter);
            }
        }
        if (config_.params.find("profile_file") != config_.params.end()) {
            profile_file = config_.params.at("profile_file");
        }
        return pcap_processor::profile_pcap(input_path, bpf_filters, profile_file);
    }
    log_processor::LogType type;
    if (log_type == "gcp") {
        type = log_processor::LogType::GCP;
    } else if (log_type == "netflow") {
        type = log_processor::LogType::NetFlow;
    } else if (log_type == "zeek") {
        type = log_processor::LogType::Zeek;
    } else {
        type = log_processor::LogType::Zeek; // Default
    }
    if (type == log_processor::LogType::Zeek) {
        return log_processor::profile_zeek(input_path);
    } else if (type == log_processor::LogType::GCP) {
        return log_processor::profile_gcp(input_path);
    } else {
        return log_processor::profile_netflow(input_path);
    }
}

std::vector<std::string> MLPipeline::get_compatible_components(const std::string& component_name, bool forward) const {
    std::vector<std::string> compatible;
    if (!components_.count(component_name)) return compatible;

    const auto& comp = components_.at(component_name);
    if (forward) {
        for (const auto& [name, other_comp] : components_) {
            bool all_inputs_met = true;
            for (const auto& input : other_comp.inputs) {
                if (input == "log_dir" || input == "pcap_file" || input == "input_file") continue;
                if (input == "custom_bpf") continue;
                if (std::find(comp.outputs.begin(), comp.outputs.end(), input) == comp.outputs.end()) {
                    all_inputs_met = false;
                    break;
                }
            }
            if (all_inputs_met && name != component_name) {
                compatible.push_back(name);
            }
        }
    } else {
        for (const auto& [name, other_comp] : components_) {
            bool can_provide_inputs = false;
            for (const auto& input : comp.inputs) {
                if (std::find(other_comp.outputs.begin(), other_comp.outputs.end(), input) != other_comp.outputs.end()) {
                    can_provide_inputs = true;
                    break;
                }
            }
            if (can_provide_inputs && name != component_name) {
                compatible.push_back(name);
            }
        }
    }

    return compatible;
}

void MLPipeline::interactive_console() {
    std::cout << "Welcome to the ML Pipeline Console (type 'help' for commands)\n";
    std::string command;

    while (true) {
        std::cout << "> ";
        std::getline(std::cin, command);
        std::stringstream ss(command);
        std::string cmd;
        ss >> cmd;

        if (cmd == "exit") {
            break;
        } else if (cmd == "help") {
            std::cout << "Commands:\n"
                      << "  set input <path>        - Set input path\n"
                      << "  set output <path>       - Set output path\n"
                      << "  set param <key> <value> - Set component parameter\n"
                      << "  add <component>         - Add component to pipeline\n"
                      << "  list components         - List available components\n"
                      << "  show pipeline           - Show current pipeline\n"
                      << "  compatible <component> [forward|backward] - Show compatible components\n"
                      << "  select features         - Select features for the last extractor\n"
                      << "  save <file>             - Save configuration to file\n"
                      << "  load <file>             - Load configuration from file\n"
                      << "  run                     - Run the pipeline\n"
                      << "  clear                   - Clear pipeline configuration\n"
                      << "  exit                    - Exit console\n";
        } else if (cmd == "set") {
            std::string key;
            ss >> key;
            if (key == "input") {
                ss >> config_.input_path;
                std::cout << "Input path set to: " << config_.input_path << "\n";
            } else if (key == "output") {
                ss >> config_.output_path;
                std::cout << "Output path set to: " << config_.output_path << "\n";
            } else if (key == "param") {
                std::string param_key, param_value;
                ss >> param_key;
                std::getline(ss, param_value);
                param_value.erase(0, param_value.find_first_not_of(" \t"));

                if (param_key == "bpf_filters" && config_.params["log_type"] == "pcap") {
                    bool has_payload_filter = false;
                    std::stringstream filter_ss(param_value);
                    std::string filter;
                    while (std::getline(filter_ss, filter, ';')) {
                        if (filter

.find("payload[") != std::string::npos) {
                            has_payload_filter = true;
                            break;
                        }
                    }
                    if (has_payload_filter && config_.params.find("bpf_pre_filter") == config_.params.end()) {
                        std::cout << "Warning: 'payload[]' filters detected without a BPF pre-filter. This may process unintended packets.\n"
                                  << "Proceed anyway? (y/n): ";
                        std::string response;
                        std::getline(std::cin, response);
                        if (response.empty() || tolower(response[0]) != 'y') {
                            std::cout << "Aborting. Please specify a pre-filter with 'set param bpf_pre_filter <filter>'.\n";
                            continue;
                        }
                        config_.params["allow_payload_filters"] = "true";
                    }
                } else if (param_key == "profile_file" && config_.params["log_type"] == "pcap") {
                    std::ifstream json_file(param_value);
                    if (json_file.is_open()) {
                        try {
                            json profile_data;
                            json_file >> profile_data;
                            bool has_payload_filter = false;
                            if (profile_data.find("bpf_filters") != profile_data.end()) {
                                for (const auto& bpf : profile_data["bpf_filters"]) {
                                    std::string filter = bpf["filter"].get<std::string>();
                                    if (filter.find("payload[") != std::string::npos) {
                                        has_payload_filter = true;
                                        break;
                                    }
                                }
                            }
                            if (has_payload_filter && config_.params.find("bpf_pre_filter") == config_.params.end()) {
                                std::cout << "Warning: 'payload[]' filters detected in profile without a BPF pre-filter. This may process unintended packets.\n"
                                          << "Proceed anyway? (y/n): ";
                                std::string response;
                                std::getline(std::cin, response);
                                if (response.empty() || tolower(response[0]) != 'y') {
                                    std::cout << "Aborting. Please specify a pre-filter with 'set param bpf_pre_filter <filter>'.\n";
                                    json_file.close();
                                    continue;
                                }
                                config_.params["allow_payload_filters"] = "true";
                            }
                        } catch (const json::exception& e) {
                            std::cout << "Error parsing JSON profile: " << e.what() << "\n";
                            json_file.close();
                            continue;
                        }
                        json_file.close();
                    }
                }

                config_.params[param_key] = param_value;
                std::cout << "Parameter " << param_key << " set to: " << param_value << "\n";
            }
        } else if (cmd == "add") {
            std::string comp_name;
            ss >> comp_name;
            if (components_.count(comp_name)) {
                config_.components.push_back(comp_name);
                std::cout << "Added component: " << comp_name << "\n";
                if (components_[comp_name].type == ComponentType::Extractor) {
                    std::cout << "Run 'select features' to choose features for " << comp_name << "\n";
                }
            } else {
                std::cout << "Error: Component " << comp_name << " not found\n";
            }
        } else if (cmd == "list" && ss.str().find("components") != std::string::npos) {
            std::cout << "Available components:\n";
            for (const auto& [name, comp] : components_) {
                std::cout << "  - " << name << " (" << (comp.type == ComponentType::Extractor ? "Extractor" :
                                                       comp.type == ComponentType::Preprocessor ? "Preprocessor" : "Model") << ")\n";
            }
        } else if (cmd == "show" && ss.str().find("pipeline") != std::string::npos) {
            std::cout << "Current pipeline:\n";
            std::cout << "  Input: " << config_.input_path << "\n";
            std::cout << "  Output: " << config_.output_path << "\n";
            std::cout << "  Components:\n";
            for (const auto& comp : config_.components) {
                std::cout << "    - " << comp << "\n";
            }
            std::cout << "  Parameters:\n";
            for (const auto& [k, v] : config_.params) {
                std::cout << "    - " << k << ": " << v << "\n";
            }
        } else if (cmd == "compatible") {
            std::string comp_name, direction;
            ss >> comp_name >> direction;
            bool forward = direction.empty() || direction == "forward";
            auto compatible = get_compatible_components(comp_name, forward);
            std::cout << "Compatible components for " << comp_name << " (" << (forward ? "forward" : "backward") << "):\n";
            for (const auto& comp : compatible) {
                std::cout << "  - " << comp << "\n";
            }
        } else if (cmd == "select" && ss.str().find("features") != std::string::npos) {
            if (config_.components.empty() || components_[config_.components.back()].type != ComponentType::Extractor) {
                std::cout << "Error: No extractor component added or last component is not an extractor\n";
            } else if (config_.input_path.empty()) {
                std::cout << "Error: Set input path before selecting features\n";
            } else {
                auto comp_name = config_.components.back();
                std::string log_type = config_.params.find("log_type") != config_.params.end() ? config_.params["log_type"] : "zeek";
                if (comp_name == "pcap_extractor") log_type = "pcap";
                auto features = get_available_features(config_.input_path, log_type);
                if (features.empty()) {
                    std::cout << "Error: No features found in input data\n";
                } else {
                    std::cout << "Available features for " << comp_name << ":\n";
                    for (size_t i = 0; i < features.size(); ++i) {
                        std::cout << "  [" << i + 1 << "] " << features[i] << "\n";
                    }
                    std::cout << "Enter feature numbers (space-separated, e.g., '1 2 3') or 'all' for all features: ";
                    std::string input;
                    std::getline(std::cin, input);
                    std::stringstream iss(input);
                    std::vector<std::string> selected_features;
                    if (input == "all") {
                        selected_features = features;
                    } else {
                        int num;
                        while (iss >> num) {
                            if (num >= 1 && num <= static_cast<int>(features.size())) {
                                selected_features.push_back(features[num - 1]);
                            }
                        }
                    }
                    if (selected_features.empty()) {
                        std::cout << "No valid features selected, keeping default\n";
                    } else {
                        std::stringstream fss;
                        for (size_t i = 0; i < selected_features.size(); ++i) {
                            fss << selected_features[i];
                            if (i < selected_features.size() - 1) fss << ",";
                        }
                        config_.params["features"] = fss.str();
                        std::cout << "Selected features: " << fss.str() << "\n";
                    }
                }
            }
        } else if (cmd == "save") {
            std::string file_path;
            ss >> file_path;
            if (file_path.empty()) {
                std::cout << "Error: Please specify a file path for saving the configuration\n";
            } else {
                save_config(file_path);
            }
        } else if (cmd == "load") {
            std::string file_path;
            ss >> file_path;
            if (file_path.empty()) {
                std::cout << "Error: Please specify a file path for loading the configuration\n";
            } else {
                load_config(file_path);
            }
        } else if (cmd == "run") {
            run_pipeline(config_);
        } else if (cmd == "clear") {
            config_ = PipelineConfig();
            std::cout << "Pipeline configuration cleared\n";
        } else {
            std::cout << "Unknown command: " << cmd << ". Type 'help' for commands.\n";
        }
    }
}

} // namespace ml_pipeline