#include <algorithm>  // For std::sort
#include <cerrno>     // For errno
#include <cstdio>     // For sscanf
#include <cstring>    // For strerror
#include <string>
#include <vector>

#include "logging.hpp"
#include "module.hpp"
#include "zygisk.hpp"

using namespace std;

static inline bool starts_with(const char* str, const char* prefix) {
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

static vector<mount_info> parse_mount_info(const char* pid) {
    char path[128];
    if (pid) {
        snprintf(path, sizeof(path), "/proc/%s/mountinfo", pid);
    } else {
        snprintf(path, sizeof(path), "/proc/self/mountinfo");
    }

    FILE* fp = fopen(path, "r");
    if (!fp) return {};

    vector<mount_info> result;
    result.reserve(256);

    char line[4096];
    char root[4096], target[4096], source[4096];
    int id;

    while (fgets(line, sizeof(line), fp)) {
        // The " - " separator is the only guaranteed, unambiguous delimiter on a valid line.
        char* sep = strstr(line, " - ");
        if (!sep) continue;

        // 利用 scanf 的短路特性
        if (sscanf(line, "%d %*d %*s %4095s %4095s", &id, root, target) != 3) continue;
        if (sscanf(sep + 3, "%*s %4095s", source) != 1) continue;

        mount_info info;
        info.id = id;
        info.root = root;
        info.target = target;
        info.source = source;
        
        result.emplace_back(move(info));
    }
    fclose(fp);
    return result;
}


vector<mount_info> check_zygote_traces(uint32_t info_flags) {
    // Check traces
    auto mounts = parse_mount_info("self");
    if (mounts.empty()) return {};

    // Context setup
    const char* root_impl = [info_flags]() -> const char* {
        if (info_flags & PROCESS_ROOT_IS_APATCH) return "APatch";
        if (info_flags & PROCESS_ROOT_IS_KSU) return "KSU";
        if (info_flags & PROCESS_ROOT_IS_MAGISK) return "magisk";
        return nullptr;
    }();

    string ksu_loop;
    if (info_flags & PROCESS_ROOT_IS_KSU) {
        auto it = find_if(mounts.begin(), mounts.end(), [](const auto& m) {
            return m.target == "/data/adb/modules" && 
                   starts_with(m.source.c_str(), "/dev/block/loop");
        });
        if (it != mounts.end()) ksu_loop = it->source;
    }

    // Definition Predicate
    auto should_unmount = [&](const mount_info& m) {
        // Generic traces
        if (starts_with(m.root.c_str(), "/adb/modules")) return true;
        if (starts_with(m.target.c_str(), "/data/adb/modules")) return true;
        
        // Root specific implementation
        if (root_impl && m.source == root_impl) return true;
        
        // KSU loop device
        if (!ksu_loop.empty() && m.source == ksu_loop) return true;

        return false;
    };

    // Filter
    vector<mount_info> traces;
    traces.reserve(64);

    copy_if(mounts.begin(), mounts.end(), back_inserter(traces), should_unmount);

    // Sort the collected traces by mount ID in descending order for safe unmounting
    if (!traces.empty()) {
        sort(traces.begin(), traces.end(),
              [](const auto& a, const auto& b) {
            return a.id > b.id; // Descending
        });
    }

    LOGV("found %zu mounting traces in zygote.", traces.size());

    return traces;
}        // The " - " separator is the only guaranteed, unambiguous delimiter on a valid line.
        char* sep = strstr(line, " - ");
        if (!sep) continue;

        // 利用 scanf 的短路特性
        if (sscanf(line, "%d %*d %*s %4095s %4095s", &id, root, target) != 3) continue;
        if (sscanf(sep + 3, "%*s %4095s", source) != 1) continue;

        mount_info info;
        info.id = id;
        info.root = root;
        info.target = target;
        info.source = source;
        
        result.emplace_back(move(info));
    }
    fclose(fp);
    return result;
}


vector<mount_info> check_zygote_traces(uint32_t info_flags) {
    // Check traces
    auto mounts = parse_mount_info("self");
    if (mounts.empty()) return {};

    // Context setup
    const char* root_impl = [info_flags]() -> const char* {
        if (info_flags & PROCESS_ROOT_IS_APATCH) return "APatch";
        if (info_flags & PROCESS_ROOT_IS_KSU) return "KSU";
        if (info_flags & PROCESS_ROOT_IS_MAGISK) return "magisk";
        return nullptr;
    }();

    string ksu_loop;
    if (info_flags & PROCESS_ROOT_IS_KSU) {
        auto it = find_if(mounts.begin(), mounts.end(), [](const auto& m) {
            return m.target == "/data/adb/modules" && 
                   starts_with(m.source.c_str(), "/dev/block/loop");
        });
        if (it != mounts.end()) ksu_loop = it->source;
    }

    // Definition Predicate
    auto should_unmount = [&](const mount_info& m) {
        // Generic traces
        if (starts_with(m.root.c_str(), "/adb/modules")) return true;
        if (starts_with(m.target.c_str(), "/data/adb/modules")) return true;
        
        // Root specific implementation
        if (root_impl && m.source == root_impl) return true;
        
        // KSU loop device
        if (!ksu_loop.empty() && m.source == ksu_loop) return true;

        return false;
    };

    // Filter
    vector<mount_info> traces;
    traces.reserve(64);

    copy_if(mounts.begin(), mounts.end(), back_inserter(traces), should_unmount);

    // Sort the collected traces by mount ID in descending order for safe unmounting
    if (!traces.empty()) {
        sort(traces.begin(), traces.end(),
              [](const auto& a, const auto& b) {
            return a.id > b.id; // Descending
        });
    }

    LOGV("found %zu mounting traces in zygote.", traces.size());

    return traces;
}

    const char* mount_source_name = nullptr;
    bool is_kernelsu = false;

    if (info_flags & PROCESS_ROOT_IS_APATCH) {
        mount_source_name = "APatch";
    } else if (info_flags & PROCESS_ROOT_IS_KSU) {
        mount_source_name = "KSU";
        is_kernelsu = true;
    } else if (info_flags & PROCESS_ROOT_IS_MAGISK) {
        mount_source_name = "magisk";
    } else {
        LOGE("could not determine root implementation, aborting unmount.");
        return traces;
    }

    std::string kernel_su_module_source;
    if (is_kernelsu) {
        for (const auto& info : mount_infos) {
            if (info.target == "/data/adb/modules" && starts_with(info.source, "/dev/block/loop")) {
                kernel_su_module_source = info.source;
                LOGV("detected KernelSU loop device module source: %s",
                     kernel_su_module_source.c_str());
                break;
            }
        }
    }

    for (const auto& info : mount_infos) {
        const bool should_unmount =
            starts_with(info.root, "/adb/modules") ||
            starts_with(info.target, "/data/adb/modules") || (info.source == mount_source_name) ||
            (!kernel_su_module_source.empty() && info.source == kernel_su_module_source);

        if (should_unmount) {
            traces.push_back(info);
        }
    }

    if (traces.empty()) {
        LOGV("no relevant mount points found to unmount.");
        return traces;
    }

    // Sort the collected traces by mount ID in descending order for safe unmounting
    std::sort(traces.begin(), traces.end(),
              [](const mount_info& a, const mount_info& b) { return a.id > b.id; });

    LOGV("found %zu mounting traces in zygote.", traces.size());

    return traces;
}
