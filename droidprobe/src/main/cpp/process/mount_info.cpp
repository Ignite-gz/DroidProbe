//
// Created by ignite on 9/23/26.
//
#include "mount_info.h"

#include <fstream>
#include <regex>

namespace {
    constexpr char kMountInfoPath[] = "/proc/self/mountinfo";
    constexpr char kMountsPath[] = "/proc/self/mounts";

    /**
    * 将输出中的八进制转义字符反转义（还原）为真实的字符
    * Linux 内核在往 /proc/self/mountinfo 或 /proc/self/mounts 写入数据时，
    * 为了防止路径或名称中的特殊字符（如空格、制表符、换行符、反斜杠等）破坏以空格分隔的表格格式，
    * 会对这些字符进行八进制转义编码。
    */
    std::string unescape_mount_field(const std::string& value) {
        static const std::regex octal_regex(R"(\\([0-7]{3}))");
        std::string result = value;
        std::smatch match;

        // 循环匹配所有 \xxx 八进制转义/替换（如 \040 -> 空格）
        while (std::regex_search(result, match, octal_regex)) {
            char ch = static_cast<char>(std::stoi(match[1].str(), nullptr, 8));
            result.replace(match.position(0), match.length(0), 1, ch);
        }

        return result;
    }

    // 把 /proc/self/mountinfo 文件的一行内容解析为 MountInfo 对象
    bool parse_mountinfo_line(const std::string& line, DroidProbe::MountInfo& mount_info) {
        // 匹配格式：... mount_point mount_options ... - filesystem_type mount_source super_options
        // 因为 mountinfo 格式的第七列是数量不固定的“可选字段”
        // 用 .*? 非贪婪匹配（表示匹配任意字符，但尽可能少地匹配，直到遇到后面的 \s+-\s+ 为止）
        const std::regex re(R"(^\S+\s+\S+\s+\S+\s+\S+\s+(\S+)\s+(\S+).*?\s+-\s+(\S+)\s+(\S+)\s+(\S+))");
        std::smatch match;

        if (std::regex_search(line, match, re)) {
            mount_info.mount_point = unescape_mount_field(match[1].str());
            mount_info.mount_options = unescape_mount_field(match[2].str());
            mount_info.filesystem_type = unescape_mount_field(match[3].str());
            mount_info.mount_source = unescape_mount_field(match[4].str());
            mount_info.super_options = unescape_mount_field(match[5].str());
            return true;
        }

        return false;
    }

    // 把 /proc/self/mountinfo 文件的内容解析为 MountInfo 数组
    bool read_mount_info(std::vector<DroidProbe::MountInfo>& mount_infos) {
        std::ifstream fin(kMountInfoPath, std::ios_base::in);

        if (!fin.is_open()) {
            return false;
        }

        std::string line;
        while (std::getline(fin, line)) {
            DroidProbe::MountInfo mount_info;
            if (parse_mountinfo_line(line, mount_info)) {
                mount_infos.push_back(std::move(mount_info));
            }
        }

        return true;
    }

    // 把 /proc/self/mounts 文件的一行内容解析为 MountInfo 对象
    bool parse_mounts_line(const std::string& line, DroidProbe::MountInfo& mount_info) {
        // 匹配格式：source mount_point filesystem_type options
        const std::regex re(R"(^(\S+)\s+(\S+)\s+(\S+)\s+(\S+))");
        std::smatch match;

        if (std::regex_search(line, match, re)) {
            mount_info.mount_source = unescape_mount_field(match[1].str());
            mount_info.mount_point = unescape_mount_field(match[2].str());
            mount_info.filesystem_type = unescape_mount_field(match[3].str());
            mount_info.mount_options = unescape_mount_field(match[4].str());
            mount_info.super_options.clear();   // 这个文件中没有这一列
            return true;
        }

        return false;
    }

    // 把 /proc/self/mounts 文件的内容解析为 MountInfo 数组
    bool read_mounts(std::vector<DroidProbe::MountInfo>& mount_infos) {
        std::ifstream file(kMountsPath);

        if (!file.is_open()) {
            return false;
        }

        std::string line;
        while (std::getline(file, line)) {
            DroidProbe::MountInfo mount_info;

            if (parse_mounts_line(line, mount_info)) {
                mount_infos.push_back(std::move(mount_info));
            }
        }

        return true;
    }

    // 解析 mount 命令输出的行为 MountInfo 对象
    bool parse_mount_command_line(const std::string& line, DroidProbe::MountInfo& mount_info) {
        // 兼容新格式: "source on mount_point type filesystem_type (options)"
        // 新格式使用关键字 “on” 隔离两个字段，()包裹 options，所以使用 .+? 和 .+ 来匹配它们（字段可能中间有空格，保险起见没用 \S+）
        const std::regex re_new(R"(^(.+?)\s+on\s+(.+?)\s+type\s+(\S+)\s+\((.+)\)$)");
        // 兼容旧格式: "source mount_point filesystem_type options"
        // 因为旧格式就是用空格分开每个字段的，所以全都用 \S+ 来匹配
        const std::regex re_old(R"(^(\S+)\s+(\S+)\s+(\S+)\s+(\S+))");

        std::smatch match;
        if (std::regex_search(line, match, re_new)) {
            mount_info.mount_source     = unescape_mount_field(match[1].str());
            mount_info.mount_point      = unescape_mount_field(match[2].str());
            mount_info.filesystem_type  = unescape_mount_field(match[3].str());
            mount_info.mount_options    = unescape_mount_field(match[4].str());
            mount_info.super_options.clear();
            return true;
        }
        else if (std::regex_search(line, match, re_old)) {
            mount_info.mount_source     = unescape_mount_field(match[1].str());
            mount_info.mount_point      = unescape_mount_field(match[2].str());
            mount_info.filesystem_type  = unescape_mount_field(match[3].str());
            mount_info.mount_options    = unescape_mount_field(match[4].str());
            mount_info.super_options.clear();
            return true;
        }
        return false;
    }

    bool execute_mount(std::vector<DroidProbe::MountInfo>& mount_infos) {
        FILE* pipe = popen("mount", "r");

        if (pipe == nullptr) {
            return false;
        }

        char buffer[4096];
        while (fgets(buffer, sizeof buffer, pipe) != nullptr) {
            std::string line(buffer);

            if (!line.empty() && line.back() == '\n') {
                DroidProbe::MountInfo mount_info;
                if (parse_mount_command_line(line, mount_info)) {
                    mount_infos.push_back(std::move(mount_info));
                }
            }
        }

        return pclose(pipe) == 0;
    }
}


bool DroidProbe::get_mounts(std::vector<MountInfo>& mounts) {
    mounts.clear();

    // 第一优先级：
    // /proc/self/mountinfo
    if (read_mount_info(mounts)) {
        return true;
    }

    // 前面可能读取了一部分，然后发生了错误，所以这里也要清理前面的内容
    mounts.clear();

    // 第二优先级：
    // /proc/self/mounts
    if (read_mounts(mounts)) {
        return true;
    }

    mounts.clear();

    // 第三优先级：
    // mount
    if (execute_mount(mounts)) {
        return true;
    }

    // 如果都没有成功，那么返回 false，并且把这个 MountInfo “数组” 的内容清空
    mounts.clear();

    return false;
}
