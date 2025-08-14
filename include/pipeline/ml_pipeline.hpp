#ifndef ML_PIPELINE_HPP
#define ML_PIPELINE_HPP

#include "logslice.hpp"
#include "time_series_preprocessor.hpp"
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <memory>

namespace ml_pipeline {

enum class ComponentType { Extractor, Preprocessor, Model };

struct Component {
    std::string name;
    ComponentType type;
    std::vector<std::string> inputs;
    std::vector<std::string> outputs;
    std::function<void(const std::map<std::string, std::string>&)> execute;
};

struct PipelineConfig {
    std::string input_path;
    std::string output_path;
    std::vector<std::string> components;
    std::map<std::string, std::string> params;
};

class MLPipeline {
private:
    std::map<std::string, Component> components_;
    PipelineConfig config_; // Stateful configuration
public:
    MLPipeline();
    void register_component(const Component& component);
    void run_pipeline(const PipelineConfig& config);
    void execute_component(const std::string& component_name, const std::map<std::string, std::string>& params);
    bool validate_pipeline(const PipelineConfig& config, std::string& error) const;
    void save_config(const std::string& file_path) const;
    void load_config(const std::string& file_path); // New method
    std::vector<std::string> get_available_features(const std::string& input_path, const std::string& log_type) const;
    std::vector<std::string> get_compatible_components(const std::string& component_name, bool forward) const;
    void interactive_console();
};

} // namespace ml_pipeline

#endif