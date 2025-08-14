#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "ml_pipeline.hpp"
#include "pcap_processor.hpp"
#include "logslice.hpp"
#include "time_series_preprocessor.hpp"
#include "json.hpp"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <vector>
#include <string>

namespace fs = std::filesystem;
using json = nlohmann::json;

// Helper to redirect cout for capturing output
class CoutRedirect {
public:
    CoutRedirect() : old_(std::cout.rdbuf(buffer_.rdbuf())) {}
    ~CoutRedirect() { std::cout.rdbuf(old_); }
    std::string getOutput() const { return buffer_.str(); }
private:
    std::stringstream buffer_;
    std::streambuf* old_;
};

// Helper to simulate console input
class TestConsole {
public:
    TestConsole(const std::vector<std::string>& inputs) {
        for (const auto& input : inputs) {
            input_ << input << "\n";
        }
        old_in_ = std::cin.rdbuf(input_.rdbuf());
    }
    ~TestConsole() { std::cin.rdbuf(old_in_); }
private:
    std::stringstream input_;
    std::streambuf* old_in_;
};

// Helper to create sample Zeek log
void create_sample_zeek_log(const std::string& path) {
    std::ofstream out(path);
    out << "#fields\tts\tid.orig_h\tid.resp_h\tid.resp_p\tduration\tlabel\n";
    out << "1234567890.123456\t192.168.1.1\t8.8.8.8\t80\t0.5\tbenign\n";
    out << "1234567890.223456\t192.168.1.1\t8.8.4.4\t443\t1.2\tmalicious\n";
    out.close();
}

// Helper to create sample PCAP file (simplified, assumes libpcap format)
void create_sample_pcap(const std::string& path) {
    std::ofstream out(path, std::ios::binary);
    // Simplified PCAP header (magic number, version, etc.)
    uint32_t magic = 0xa1b2c3d4;
    uint16_t version_major = 2, version_minor = 4;
    int32_t thiszone = 0;
    uint32_t sigfigs = 0, snaplen = 65535, network = 1; // Ethernet
    out.write(reinterpret_cast<const char*>(&magic), 4);
    out.write(reinterpret_cast<const char*>(&version_major), 2);
    out.write(reinterpret_cast<const char*>(&version_minor), 2);
    out.write(reinterpret_cast<const char*>(&thiszone), 4);
    out.write(reinterpret_cast<const char*>(&sigfigs), 4);
    out.write(reinterpret_cast<const char*>(&snaplen), 4);
    out.write(reinterpret_cast<const char*>(&network), 4);
    // Sample packet (Ethernet + IPv4 + TCP, minimal)
    uint32_t ts_sec = 1234567890, ts_usec = 123456;
    uint32_t incl_len = 54, orig_len = 54;
    uint8_t eth_hdr[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08,0x00};
    uint8_t ip_hdr[] = {0x45,0x00,0x00,0x28,0x00,0x00,0x40,0x00,0x40,0x06,0x00,0x00,0xc0,0xa8,0x01,0x01,0x08,0x08,0x08,0x08};
    uint8_t tcp_hdr[] = {0x00,0x50,0x00,0x50,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x50,0x02,0x72,0x10,0x00,0x00,0x00,0x00};
    out.write(reinterpret_cast<const char*>(&ts_sec), 4);
    out.write(reinterpret_cast<const char*>(&ts_usec), 4);
    out.write(reinterpret_cast<const char*>(&incl_len), 4);
    out.write(reinterpret_cast<const char*>(&orig_len), 4);
    out.write(reinterpret_cast<const char*>(&eth_hdr), 14);
    out.write(reinterpret_cast<const char*>(&ip_hdr), 20);
    out.write(reinterpret_cast<const char*>(&tcp_hdr), 20);
    out.close();
}

// Helper to create sample JSON profile
void create_sample_json_profile(const std::string& path) {
    std::ofstream out(path);
    out << R"({
        "bpf_filters": [
            {"name": "modbus_id", "filter": "tcp[0:2]"},
            {"name": "func_code", "filter": "tcp[7]"}
        ]
    })";
    out.close();
}

// Helper to create sample suspicion profile
void create_sample_suspicion_profile(const std::string& path) {
    std::ofstream out(path);
    out << R"({
        "rules": [
            {"feature": "packet_size", "condition": "greater_than", "value": 100},
            {"feature": "protocol", "condition": "equals", "value": 6}
        ],
        "threshold": 1
    })";
    out.close();
}

TEST_CASE("MLPipeline Console Commands", "[console]") {
    ml_pipeline::MLPipeline pipeline;
    CoutRedirect cout_redirect;
    std::string tmp_dir = "test_tmp";
    fs::create_directory(tmp_dir);

    SECTION("Help Command") {
        TestConsole console({"help"});
        pipeline.interactive_console();
        auto output = cout_redirect.getOutput();
        REQUIRE(output.find("set input <path>") != std::string::npos);
        REQUIRE(output.find("add <component>") != std::string::npos);
        REQUIRE(output.find("select features") != std::string::npos);
    }

    SECTION("List Components") {
        TestConsole console({"list components", "exit"});
        pipeline.interactive_console();
        auto output = cout_redirect.getOutput();
        REQUIRE(output.find("- zeek_extractor (Extractor)") != std::string::npos);
        REQUIRE(output.find("- pcap_extractor (Extractor)") != std::string::npos);
        REQUIRE(output.find("- time_series_preprocessor (Preprocessor)") != std::string::npos);
        REQUIRE(output.find("- isolation_forest (Model)") != std::string::npos);
    }

    SECTION("Set Input and Output") {
        TestConsole console({
            "set input " + tmp_dir + "/input",
            "set output " + tmp_dir + "/output.csv",
            "show pipeline",
            "exit"
        });
        pipeline.interactive_console();
        auto output = cout_redirect.getOutput();
        REQUIRE(output.find("Input path set to: " + tmp_dir + "/input") != std::string::npos);
        REQUIRE(output.find("Output path set to: " + tmp_dir + "/output.csv") != std::string::npos);
        REQUIRE(output.find("Input: " + tmp_dir + "/input") != std::string::npos);
        REQUIRE(output.find("Output: " + tmp_dir + "/output.csv") != std::string::npos);
    }

    SECTION("Add Components") {
        TestConsole console({
            "add zeek_extractor",
            "add pcap_extractor",
            "add time_series_preprocessor",
            "add isolation_forest",
            "show pipeline",
            "exit"
        });
        pipeline.interactive_console();
        auto output = cout_redirect.getOutput();
        REQUIRE(output.find("Added component: zeek_extractor") != std::string::npos);
        REQUIRE(output.find("Added component: pcap_extractor") != std::string::npos);
        REQUIRE(output.find("Added component: time_series_preprocessor") != std::string::npos);
        REQUIRE(output.find("Added component: isolation_forest") != std::string::npos);
        REQUIRE(output.find("Components:\n    - zeek_extractor\n    - pcap_extractor\n    - time_series_preprocessor\n    - isolation_forest") != std::string::npos);
    }

    SECTION("Compatible Components") {
        TestConsole console({
            "compatible pcap_extractor forward",
            "compatible isolation_forest backward",
            "exit"
        });
        pipeline.interactive_console();
        auto output = cout_redirect.getOutput();
        REQUIRE(output.find("Compatible components for pcap_extractor (forward):\n  - time_series_preprocessor") != std::string::npos);
        REQUIRE(output.find("Compatible components for isolation_forest (backward):\n  - time_series_preprocessor") != std::string::npos);
    }

    SECTION("Clear Pipeline") {
        TestConsole console({
            "set input " + tmp_dir + "/input",
            "add pcap_extractor",
            "show pipeline",
            "clear",
            "show pipeline",
            "exit"
        });
        pipeline.interactive_console();
        auto output = cout_redirect.getOutput();
        REQUIRE(output.find("Input: " + tmp_dir + "/input") != std::string::npos);
        REQUIRE(output.find("Components:\n    - pcap_extractor") != std::string::npos);
        REQUIRE(output.find("Pipeline configuration cleared") != std::string::npos);
        REQUIRE(output.find("Input: \n  Output: \n  Components:") != std::string::npos);
    }
}

TEST_CASE("Save and Load Configuration", "[console][save][load]") {
    ml_pipeline::MLPipeline pipeline;
    CoutRedirect cout_redirect;
    std::string tmp_dir = "test_tmp";
    fs::create_directory(tmp_dir);
    std::string config_file = tmp_dir + "/config.json";

    // Test saving configuration
    TestConsole console_save({
        "set input test.pcap",
        "set output output.csv",
        "set param log_type pcap",
        "set param features packetsize,protocol",
        "add pcap_extractor",
        "add time_series_preprocessor",
        "save " + config_file,
        "exit"
    });
    pipeline.interactive_console();
    auto output_save = cout_redirect.getOutput();
    REQUIRE(output_save.find("Configuration saved to: " + config_file) != std::string::npos);

    std::ifstream in(config_file);
    REQUIRE(in.good());
    json config_data;
    in >> config_data;
    in.close();
    REQUIRE(config_data["input_path"] == "test.pcap");
    REQUIRE(config_data["output_path"] == "output.csv");
    REQUIRE(config_data["components"] == std::vector<std::string>{"pcap_extractor", "time_series_preprocessor"});
    REQUIRE(config_data["params"]["log_type"] == "pcap");
    REQUIRE(config_data["params"]["features"] == "packetsize,protocol");

    // Test loading configuration
    pipeline = ml_pipeline::MLPipeline(); // Reset pipeline
    CoutRedirect cout_redirect_load;
    TestConsole console_load({
        "load " + config_file,
        "show pipeline",
        "exit"
    });
    pipeline.interactive_console();
    auto output_load = cout_redirect_load.getOutput();
    REQUIRE(output_load.find("Configuration loaded from: " + config_file) != std::string::npos);
    REQUIRE(output_load.find("Input: test.pcap") != std::string::npos);
    REQUIRE(output_load.find("Output: output.csv") != std::string::npos);
    REQUIRE(output_load.find("Components:\n    - pcap_extractor\n    - time_series_preprocessor") != std::string::npos);
    REQUIRE(output_load.find("Parameters:\n    - log_type: pcap\n    - features: packetsize,protocol") != std::string::npos);
}

TEST_CASE("Zeek Extractor", "[zeek_extractor]") {
    ml_pipeline::MLPipeline pipeline;
    CoutRedirect cout_redirect;
    std::string tmp_dir = "test_tmp";
    fs::create_directory(tmp_dir);
    std::string log_file = tmp_dir + "/conn.log";
    std::string output_file = tmp_dir + "/output.csv";

    create_sample_zeek_log(log_file);

    SECTION("Run Zeek Extractor") {
        TestConsole console({
            "set input " + tmp_dir,
            "set output " + output_file,
            "set param log_type zeek",
            "set param features ts,id.orig_h,id.resp_h",
            "add zeek_extractor",
            "run",
            "exit"
        });
        pipeline.interactive_console();
        auto output = cout_redirect.getOutput();
        REQUIRE(output.find("Executing component: zeek_extractor") != std::string::npos);
        REQUIRE(output.find("Processed 2 lines from") != std::string::npos);
        REQUIRE(output.find("(Malicious: 1, Benign: 1)") != std::string::npos);

        std::ifstream out(output_file);
        REQUIRE(out.good());
        std::string line;
        std::getline(out, line);
        REQUIRE(line == "ts,id.orig_h,id.resp_h,label");
        std::getline(out, line);
        REQUIRE(line.find("1234567890.123456,192.168.1.1,8.8.8.8,0") != std::string::npos);
        std::getline(out, line);
        REQUIRE(line.find("1234567890.223456,192.168.1.1,8.8.4.4,1") != std::string::npos);
        out.close();
    }

    SECTION("Invalid Input Directory") {
        TestConsole console({
            "set input " + tmp_dir + "/nonexistent",
            "set output " + output_file,
            "set param log_type zeek",
            "add zeek_extractor",
            "run",
            "exit"
        });
        pipeline.interactive_console();
        auto output = cout_redirect.getOutput();
        REQUIRE(output.find("Error: Input '" + tmp_dir + "/nonexistent' is neither a valid file nor a directory for log type") != std::string::npos);
    }
}

TEST_CASE("PCAP Extractor", "[pcap_extractor]") {
    ml_pipeline::MLPipeline pipeline;
    CoutRedirect cout_redirect;
    std::string tmp_dir = "test_tmp";
    fs::create_directory(tmp_dir);
    std::string pcap_file = tmp_dir + "/sample.pcap";
    std::string output_file = tmp_dir + "/output.csv";
    std::string profile_file = tmp_dir + "/profile.json";
    std::string suspicion_file = tmp_dir + "/suspicion.json";

    create_sample_pcap(pcap_file);
    create_sample_json_profile(profile_file);
    create_sample_suspicion_profile(suspicion_file);

    SECTION("Run PCAP Extractor with Features") {
        TestConsole console({
            "set input " + pcap_file,
            "set output " + output_file,
            "set param log_type pcap",
            "set param verbose true",
            "set param features packetsize,srcip,timestamp",
            "add pcap_extractor",
            "run",
            "exit"
        });
        pipeline.interactive_console();
        auto output = cout_redirect.getOutput();
        REQUIRE(output.find("Executing component: pcap_extractor") != std::string::npos);
        REQUIRE(output.find("[pcap_processor] Processing packet with timestamp") != std::string::npos);
        REQUIRE(output.find("[pcap_processor] Processed PCAP file " + pcap_file + " to " + output_file) != std::string::npos);

        std::ifstream out(output_file);
        REQUIRE(out.good());
        std::string line;
        std::getline(out, line);
        REQUIRE(line == "packetsize,srcip,timestamp");
        std::getline(out, line);
        REQUIRE(line.find("54,192.168.1.1,1234567890.123456") != std::string::npos);
        out.close();
    }

    SECTION("Payload Filter Warning - Proceed") {
        TestConsole console({
            "set input " + pcap_file,
            "set output " + output_file,
            "set param log_type pcap",
            "set param bpf_filters thing=payload[7]",
            "y",
            "add pcap_extractor",
            "select features",
            "1 16",
            "run",
            "exit"
        });
        pipeline.interactive_console();
        auto output = cout_redirect.getOutput();
        REQUIRE(output.find("Warning: 'payload[]' filters detected without a BPF pre-filter") != std::string::npos);
        REQUIRE(output.find("Parameter bpf_filters set to: thing=payload[7]") != std::string::npos);
        REQUIRE(output.find("Parameter allow_payload_filters set to: true") != std::string::npos);
        REQUIRE(output.find("Selected features: packetsize,thing") != std::string::npos);
        REQUIRE(output.find("Executing component: pcap_extractor") != std::string::npos);

        std::ifstream out(output_file);
        REQUIRE(out.good());
        std::string line;
        std::getline(out, line);
        REQUIRE(line == "packetsize,thing");
        out.close();
    }

    SECTION("Payload Filter Warning - Abort") {
        TestConsole console({
            "set input " + pcap_file,
            "set output " + output_file,
            "set param log_type pcap",
            "set param bpf_filters thing=payload[7]",
            "n",
            "exit"
        });
        pipeline.interactive_console();
        auto output = cout_redirect.getOutput();
        REQUIRE(output.find("Warning: 'payload[]' filters detected without a BPF pre-filter") != std::string::npos);
        REQUIRE(output.find("Aborting. Please specify a pre-filter with 'set param bpf_pre_filter <filter>'") != std::string::npos);
        REQUIRE(output.find("Parameter bpf_filters set to: thing=payload[7]") == std::string::npos);
    }

    SECTION("Profile File with Payload Filter") {
        TestConsole console({
            "set input " + pcap_file,
            "set output " + output_file,
            "set param log_type pcap",
            "set param profile_file " + profile_file,
            "y",
            "add pcap_extractor",
            "select features",
            "1 16",
            "run",
            "exit"
        });
        pipeline.interactive_console();
        auto output = cout_redirect.getOutput();
        REQUIRE(output.find("Warning: 'payload[]' filters detected in profile without a BPF pre-filter") != std::string::npos);
        REQUIRE(output.find("Parameter allow_payload_filters set to: true") != std::string::npos);
        REQUIRE(output.find("Selected features: packetsize,modbus_id") != std::string::npos);
    }

    SECTION("Invalid PCAP File") {
        TestConsole console({
            "set input " + tmp_dir + "/nonexistent.pcap",
            "set output " + output_file,
            "set param log_type pcap",
            "add pcap_extractor",
            "run",
            "exit"
        });
        pipeline.interactive_console();
        auto output = cout_redirect.getOutput();
        REQUIRE(output.find("[pcap_processor] Error opening " + tmp_dir + "/nonexistent.pcap") != std::string::npos);
    }
}

TEST_CASE("Save Configuration", "[console][save]") {
    ml_pipeline::MLPipeline pipeline;
    CoutRedirect cout_redirect;
    std::string tmp_dir = "test_tmp";
    fs::create_directory(tmp_dir);
    std::string config_file = tmp_dir + "/config.json";

    TestConsole console({
        "set input test.pcap",
        "set output output.csv",
        "set param log_type pcap",
        "add pcap_extractor",
        "save " + config_file,
        "exit"
    });
    pipeline.interactive_console();
    auto output = cout_redirect.getOutput();
    REQUIRE(output.find("Configuration saved to: " + config_file) != std::string::npos);

    std::ifstream in(config_file);
    REQUIRE(in.good());
    json config_data;
    in >> config_data;
    in.close();
    REQUIRE(config_data["input_path"] == "test.pcap");
    REQUIRE(config_data["output_path"] == "output.csv");
    REQUIRE(config_data["components"] == std::vector<std::string>{"pcap_extractor"});
    REQUIRE(config_data["params"]["log_type"] == "pcap");
}

TEST_CASE("Time Series Preprocessor", "[preprocessor]") {
    ml_pipeline::MLPipeline pipeline;
    CoutRedirect cout_redirect;
    std::string tmp_dir = "test_tmp";
    fs::create_directory(tmp_dir);
    std::string input_file = tmp_dir + "/input.csv";
    std::string output_file = tmp_dir + "/output.csv";

    // Create sample input CSV
    std::ofstream in(input_file);
    in << "timestamp,packetsize,protocol,label\n";
    in << "1234567890.123456,100,6,0\n";
    in << "1234567890.223456,200,6,1\n";
    in.close();

    SECTION("Run Preprocessor") {
        TestConsole console({
            "set input " + input_file,
            "set output " + output_file,
            "set param log_type csv",
            "set param features packetsize,protocol",
            "set param window_size 1.0",
            "set param normalize true",
            "add time_series_preprocessor",
            "run",
            "exit"
        });
        pipeline.interactive_console();
        auto output = cout_redirect.getOutput();
        REQUIRE(output.find("Executing component: time_series_preprocessor") != std::string::npos);
        REQUIRE(output.find("Preprocessing completed. Output saved to " + output_file) != std::string::npos);

        std::ifstream out(output_file);
        REQUIRE(out.good());
        std::string line;
        std::getline(out, line);
        REQUIRE(line == "timestamp,packetsize,protocol,label");
        std::getline(out, line);
        REQUIRE(line.find("1234567890.123456") != std::string::npos);
        out.close();
    }
}

TEST_CASE("Full Pipeline", "[pipeline]") {
    ml_pipeline::MLPipeline pipeline;
    CoutRedirect cout_redirect;
    std::string tmp_dir = "test_tmp";
    fs::create_directory(tmp_dir);
    std::string pcap_file = tmp_dir + "/sample.pcap";
    std::string output_file = tmp_dir + "/output.csv";
    std::string suspicion_file = tmp_dir + "/suspicion.json";

    create_sample_pcap(pcap_file);
    create_sample_suspicion_profile(suspicion_file);

    SECTION("PCAP -> Preprocessor -> Model") {
        TestConsole console({
            "set input " + pcap_file,
            "set output " + output_file,
            "set param log_type pcap",
            "set param verbose true",
            "set param label_file " + suspicion_file,
            "add pcap_extractor",
            "select features",
            "1 3 8",
            "set param features packetsize,protocol",
            "set param window_size 1.0",
            "set param normalize true",
            "add time_series_preprocessor",
            "add isolation_forest",
            "run",
            "exit"
        });
        pipeline.interactive_console();
        auto output = cout_redirect.getOutput();
        REQUIRE(output.find("Executing component: pcap_extractor") != std::string::npos);
        REQUIRE(output.find("[pcap_processor] Processed PCAP file") != std::string::npos);
        REQUIRE(output.find("Executing component: time_series_preprocessor") != std::string::npos);
        REQUIRE(output.find("Preprocessing completed") != std::string::npos);
        REQUIRE(output.find("Executing component: isolation_forest") != std::string::npos);
        REQUIRE(output.find("[isolation_forest] Training Isolation Forest model (placeholder)") != std::string::npos);

        std::ifstream out(output_file);
        REQUIRE(out.good());
        std::string line;
        std::getline(out, line);
        REQUIRE(line == "packetsize,protocol,timestamp");
        out.close();
    }
}

// Clean up
TEST_CASE("Cleanup", "[cleanup]") {
    fs::remove_all("test_tmp");
}