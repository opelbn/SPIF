#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#include <sstream>
#include "cnpy.h"

namespace fs = std::filesystem;

std::vector<std::string> split(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(str);
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

double encode_protocol(const std::string& protocol) {
    if (protocol == "tcp") return 1.0;
    if (protocol == "udp") return 2.0;
    if (protocol == "icmp") return 3.0;
    return 0.0;
}

double encode_service(const std::string& service) {
    if (service == "-") return 0.0;
    if (service == "http") return 1.0;
    if (service == "dns") return 2.0;
    if (service == "ftp") return 3.0;
    if (service == "ssh") return 4.0;
    if (service == "smtp") return 5.0;
    return 6.0;
}

double parse_double(const std::string& value) {
    try {
        return std::stod(value);
    } catch (...) {
        return 0.0;
    }
}

void preprocess_files(const std::string& input_dir) {
    const size_t CHUNK_SIZE = 10'000'000; // Process 10 million rows at a time
    std::vector<std::vector<double>> X_data;
    std::vector<double> y_data;
    int malformed_lines = 0;
    int malformed_malicious = 0;
    int malformed_benign = 0;
    size_t total_rows = 0;
    int chunk_number = 0;

    for (const auto& entry : fs::directory_iterator(input_dir)) {
        if (entry.path().extension() != ".csv") continue;

        std::ifstream file(entry.path());
        std::string line;
        std::getline(file, line); // Skip header

        while (std::getline(file, line)) {
            auto tokens = split(line, ',');
            if (tokens.size() != 10) {
                malformed_lines++;
                double label = -1;
                if (tokens.size() >= 10) {
                    label = parse_double(tokens[9]);
                } else if (!tokens.empty()) {
                    label = parse_double(tokens.back());
                }
                if (label == 1.0) malformed_malicious++;
                else if (label == 0.0) malformed_benign++;

                while (tokens.size() < 10) {
                    tokens.push_back("0");
                }
                if (tokens.size() > 10) {
                    tokens.resize(10);
                }
            }

            std::string protocol = tokens[0];
            std::string service = tokens[1];
            double protocol_encoded = encode_protocol(protocol);
            double service_encoded = encode_service(service);

            std::vector<double> features;
            features.push_back(protocol_encoded);
            features.push_back(service_encoded);
            features.push_back(parse_double(tokens[2]));
            features.push_back(parse_double(tokens[3]));
            features.push_back(parse_double(tokens[4]));
            features.push_back(parse_double(tokens[5]));
            features.push_back(parse_double(tokens[6]));
            features.push_back(parse_double(tokens[7]));
            features.push_back(parse_double(tokens[8]));

            X_data.push_back(features);

            double label = parse_double(tokens[9]);
            y_data.push_back(label);

            total_rows++;

            // Save chunk if we reach CHUNK_SIZE
            if (X_data.size() >= CHUNK_SIZE) {
                const unsigned int X_rows = X_data.size();
                const unsigned int X_cols = X_data[0].size();
                std::vector<double> X_flat;
                X_flat.reserve(X_rows * X_cols);
                for (const auto& row : X_data) {
                    X_flat.insert(X_flat.end(), row.begin(), row.end());
                }

                std::string x_chunk_file = "X_chunk_" + std::to_string(chunk_number) + ".npy";
                std::string y_chunk_file = "y_chunk_" + std::to_string(chunk_number) + ".npy";
                cnpy::npy_save(x_chunk_file.c_str(), X_flat.data(), {X_rows, X_cols}, "w");
                cnpy::npy_save(y_chunk_file.c_str(), y_data.data(), {y_data.size()}, "w");

                std::cout << "Saved chunk " << chunk_number << " with " << X_rows << " rows." << std::endl;

                X_data.clear();
                y_data.clear();
                chunk_number++;
            }
        }
    }

    // Save the last chunk if it exists
    if (!X_data.empty()) {
        const unsigned int X_rows = X_data.size();
        const unsigned int X_cols = X_data[0].size();
        std::vector<double> X_flat;
        X_flat.reserve(X_rows * X_cols);
        for (const auto& row : X_data) {
            X_flat.insert(X_flat.end(), row.begin(), row.end());
        }

        std::string x_chunk_file = "X_chunk_" + std::to_string(chunk_number) + ".npy";
        std::string y_chunk_file = "y_chunk_" + std::to_string(chunk_number) + ".npy";
        cnpy::npy_save(x_chunk_file.c_str(), X_flat.data(), {X_rows, X_cols}, "w");
        cnpy::npy_save(y_chunk_file.c_str(), y_data.data(), {y_data.size()}, "w");

        std::cout << "Saved final chunk " << chunk_number << " with " << X_rows << " rows." << std::endl;
        chunk_number++;
    }

    std::cout << "Total malformed lines: " << malformed_lines << std::endl;
    std::cout << "Malformed Malicious: " << malformed_malicious << std::endl;
    std::cout << "Malformed Benign: " << malformed_benign << std::endl;
    std::cout << "Processed " << total_rows << " rows with 9 features." << std::endl;
    std::cout << "Saved " << chunk_number << " chunks. Run the Python script to combine them into X.npy and y.npy." << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <input_dir>" << std::endl;
        return 1;
    }
    preprocess_files(argv[1]);
    return 0;
}