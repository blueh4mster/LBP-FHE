// #pragma once
// #include <fstream>
// #include <string>
// #include <cstdio>
// #include <cstdlib>
// #include <fstream>
// #include <sstream>
// #include <regex>


// namespace benchutils {

// inline size_t get_rss_kb() {
//     std::ifstream f("/proc/self/status");
//     std::string line;
//     while (std::getline(f, line)) {
//         if (line.rfind("VmRSS:", 0) == 0) {
//             size_t rss_kb;
//             sscanf(line.c_str(), "VmRSS: %zu kB", &rss_kb);
//             return rss_kb;
//         }
//     }
//     return 0;
// }

// // === Utility functions (Raspberry Pi 4) ===
// inline long get_cpu_freq() {
//     FILE* pipe = popen("vcgencmd measure_clock arm", "r");
//     if (!pipe) return 0;
//     char buffer[128];
//     fgets(buffer, sizeof(buffer), pipe);
//     pclose(pipe);
//     std::string out(buffer);
//     size_t pos = out.find("=");
//     return (pos != std::string::npos) ? std::stol(out.substr(pos + 1)) : 0; // Hz
// }

// inline double get_cpu_volt() {
//     FILE* pipe = popen("vcgencmd measure_volts core", "r");
//     if (!pipe) return 0.0;
//     char buffer[128];
//     fgets(buffer, sizeof(buffer), pipe);
//     pclose(pipe);
//     std::string out(buffer);
//     out.erase(0, out.find("=") + 1);
//     out.erase(out.find("V"));
//     return std::stod(out);
// }

// // === Power estimation model for Raspberry Pi 4 ===
// inline double estimate_power(double volt, long freq_hz, double active_cores = 1.0) {
//     const double C = 3.0e-9; // calibration constant for Pi4 (approximate)
//     const double idle = 1.2; // baseline idle watts (Pi4 higher than Pi3)
//     return idle + C * (volt * volt) * freq_hz * active_cores;
// }

// } // namespace benchutils

#pragma once
#include <fstream>
#include <string>
#include <vector>
#include <filesystem>
#include <unistd.h>

namespace benchutils {

// === Actual RSS in KB ===
inline size_t get_rss_kb() {
    long rss_pages = 0;
    std::ifstream f("/proc/self/statm");
    if (f) {
        long total_pages;
        f >> total_pages >> rss_pages;
    }
    long page_size_kb = sysconf(_SC_PAGESIZE) / 1024;
    return rss_pages * page_size_kb;
}

// === Energy reading from Intel RAPL (microjoules) ===
// Works on Intel CPUs supporting powercap (use `ls /sys/class/powercap` to check)
inline std::vector<double> read_rapl_energy_uj() {
    std::vector<double> energies;
    std::string base_path = "/sys/class/powercap";
    namespace fs = std::filesystem;

    if (!fs::exists(base_path)) return energies;

    for (const auto& entry : fs::directory_iterator(base_path)) {
        if (entry.path().string().find("intel-rapl") != std::string::npos) {
            std::string file = entry.path().string() + "/energy_uj";
            std::ifstream f(file);
            if (f) {
                double uj;
                f >> uj;
                energies.push_back(uj);
            }
        }
    }
    return energies;
}

// === Total CPU energy in Joules ===
inline double get_total_cpu_energy_j() {
    auto energies = read_rapl_energy_uj();
    double total = 0.0;
    for (auto e : energies) total += e;
    return total; // µJ
}

} // namespace benchutils
