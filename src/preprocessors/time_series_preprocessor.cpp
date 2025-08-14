#include "time_series_preprocessor.hpp"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <cmath>
#include <numeric>
#include <iomanip>

namespace time_series_preprocessor {

TimeSeriesPreprocessor::TimeSeriesPreprocessor(const TimeSeriesConfig& config)
    : config_(config) {}

void TimeSeriesPreprocessor::preprocess() {
    load_csv();
    aggregate_windows();
    if (config_.normalize) {
        normalize_features();
    }
    save_output();
}

const std::vector<TimeSeriesPoint>& TimeSeriesPreprocessor::get_preprocessed_data() const {
    return preprocessed_data_;
}

void TimeSeriesPreprocessor::load_csv() {
    std::ifstream in(config_.input_file);
    if (!in) {
        std::cerr << "Error: Could not open input file " << config_.input_file << "\n";
        return;
    }

    std::string line;
    // Read header
    if (std::getline(in, line)) {
        std::stringstream ss(line);
        std::string token;
        while (std::getline(ss, token, ',')) {
            headers_.push_back(token);
        }
    }

    // Read data
    while (std::getline(in, line)) {
        std::stringstream ss(line);
        std::vector<std::string> values;
        std::string token;
        while (std::getline(ss, token, ',')) {
            values.push_back(token);
        }

        if (values.size() != headers_.size()) {
            std::cerr << "Warning: Malformed line in CSV, skipping\n";
            continue;
        }

        TimeSeriesPoint point;
        for (size_t i = 0; i < headers_.size(); ++i) {
            if (headers_[i] == config_.timestamp_column) {
                try {
                    point.timestamp = std::stod(values[i]);
                } catch (const std::exception& e) {
                    std::cerr << "Warning: Invalid timestamp '" << values[i] << "', skipping\n";
                    continue;
                }
            } else if (headers_[i] == config_.label_column && !config_.label_column.empty()) {
                try {
                    point.label = std::stoi(values[i]);
                } catch (const std::exception&) {
                    point.label = 0;
                }
            } else if (std::find(config_.features.begin(), config_.features.end(), headers_[i]) != config_.features.end()) {
                try {
                    point.features[headers_[i]] = std::stod(values[i]);
                } catch (const std::exception&) {
                    point.features[headers_[i]] = 0.0;
                }
            }
        }
        preprocessed_data_.push_back(point);
    }
}

void TimeSeriesPreprocessor::aggregate_windows() {
    if (preprocessed_data_.empty()) return;

    std::sort(preprocessed_data_.begin(), preprocessed_data_.end(),
              [](const TimeSeriesPoint& a, const TimeSeriesPoint& b) {
                  return a.timestamp < b.timestamp;
              });

    std::vector<TimeSeriesPoint> aggregated_data;
    double window_start = preprocessed_data_[0].timestamp;
    TimeSeriesPoint current_point;
    current_point.timestamp = window_start;
    std::unordered_map<std::string, std::vector<double>> feature_values;
    std::vector<int> labels;

    for (const auto& point : preprocessed_data_) {
        if (point.timestamp >= window_start + config_.window_size_seconds) {
            // Finalize current window
            for (const auto& feature : config_.features) {
                auto& values = feature_values[feature];
                double avg = values.empty() ? 0.0 : std::accumulate(values.begin(), values.end(), 0.0) / values.size();
                current_point.features[feature] = avg;
                values.clear();
            }
            current_point.label = labels.empty() ? 0 : (*std::max_element(labels.begin(), labels.end()));
            aggregated_data.push_back(current_point);

            // Start new window
            window_start = std::floor(point.timestamp / config_.window_size_seconds) * config_.window_size_seconds;
            current_point = TimeSeriesPoint();
            current_point.timestamp = window_start;
            labels.clear();
        }

        for (const auto& feature : config_.features) {
            if (point.features.count(feature)) {
                feature_values[feature].push_back(point.features.at(feature));
            }
        }
        if (!config_.label_column.empty()) {
            labels.push_back(point.label);
        }
    }

    // Finalize last window
    if (!feature_values.empty()) {
        for (const auto& feature : config_.features) {
            auto& values = feature_values[feature];
            double avg = values.empty() ? 0.0 : std::accumulate(values.begin(), values.end(), 0.0) / values.size();
            current_point.features[feature] = avg;
        }
        current_point.label = labels.empty() ? 0 : (*std::max_element(labels.begin(), labels.end()));
        aggregated_data.push_back(current_point);
    }

    preprocessed_data_ = std::move(aggregated_data);
}

void TimeSeriesPreprocessor::normalize_features() {
    // Compute mean and std for each feature
    for (const auto& feature : config_.features) {
        double sum = 0.0;
        double sum_sq = 0.0;
        size_t count = 0;

        for (const auto& point : preprocessed_data_) {
            if (point.features.count(feature)) {
                double val = point.features.at(feature);
                sum += val;
                sum_sq += val * val;
                count++;
            }
        }

        feature_means_[feature] = count > 0 ? sum / count : 0.0;
        double variance = count > 1 ? (sum_sq / count - feature_means_[feature] * feature_means_[feature]) : 0.0;
        feature_stds_[feature] = variance > 0 ? std::sqrt(variance) : 1.0;
    }

    // Normalize features
    for (auto& point : preprocessed_data_) {
        for (const auto& feature : config_.features) {
            if (point.features.count(feature)) {
                double val = point.features[feature];
                point.features[feature] = (val - feature_means_[feature]) / feature_stds_[feature];
            }
        }
    }
}

void TimeSeriesPreprocessor::save_output() {
    std::ofstream out(config_.output_file);
    if (!out) {
        std::cerr << "Error: Could not open output file " << config_.output_file << "\n";
        return;
    }

    // Write header
    out << config_.timestamp_column;
    for (const auto& feature : config_.features) {
        out << "," << feature;
    }
    if (!config_.label_column.empty()) {
        out << "," << config_.label_column;
    }
    out << "\n";

    // Write data
    for (const auto& point : preprocessed_data_) {
        out << std::fixed << std::setprecision(6) << point.timestamp;
        for (const auto& feature : config_.features) {
            out << "," << (point.features.count(feature) ? point.features.at(feature) : 0.0);
        }
        if (!config_.label_column.empty()) {
            out << "," << point.label;
        }
        out << "\n";
    }
}

} // namespace time_series_preprocessor