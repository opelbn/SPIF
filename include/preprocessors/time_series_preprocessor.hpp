#ifndef TIME_SERIES_PREPROCESSOR_HPP
#define TIME_SERIES_PREPROCESSOR_HPP

#include <vector>
#include <string>
#include <map>
#include <chrono>
#include <unordered_map>

namespace time_series_preprocessor {

struct TimeSeriesConfig {
    std::string input_file;           // Input CSV file (from log_processor or TEX)
    std::string output_file;          // Output file for preprocessed data
    std::vector<std::string> features; // Features to preprocess (e.g., packet_size, arrival_interval)
    double window_size_seconds;       // Time window for aggregation (e.g., 1.0 for 1 second)
    bool normalize;                   // Whether to normalize features
    std::string timestamp_column;     // Name of the timestamp column (e.g., "timestamp")
    std::string label_column;         // Name of the label column (e.g., "label"), if present
};

struct TimeSeriesPoint {
    double timestamp;                          // Aggregated timestamp (window start)
    std::unordered_map<std::string, double> features; // Feature values (e.g., avg_packet_size)
    int label;                                 // Aggregated label (e.g., 1 if any event is suspicious)
};

class TimeSeriesPreprocessor {
public:
    TimeSeriesPreprocessor(const TimeSeriesConfig& config);
    void preprocess();
    const std::vector<TimeSeriesPoint>& get_preprocessed_data() const;

private:
    TimeSeriesConfig config_;
    std::vector<TimeSeriesPoint> preprocessed_data_;
    std::vector<std::string> headers_;
    std::unordered_map<std::string, double> feature_means_;
    std::unordered_map<std::string, double> feature_stds_;

    void load_csv();
    void aggregate_windows();
    void normalize_features();
    void save_output();
};

} // namespace time_series_preprocessor

#endif // TIME_SERIES_PREPROCESSOR_HPP