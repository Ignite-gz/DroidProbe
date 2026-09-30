//
// Created by ignite on 9/30/26.
//

#include "native_detector_utils.h"

bool DroidProbe::Root::HasPendingJavaException(JNIEnv* env) {
    return env == nullptr || env->ExceptionCheck() == JNI_TRUE;
} /* HasPendingJavaException */

bool DroidProbe::Root::AppendJavaEvidence(JNIEnv* env, jobject evidence_list, jmethodID list_add_method,
    jclass evidence_class, jmethodID evidence_constructor,
    const NativeEvidence& evidence) {
    if (env == nullptr || evidence_list == nullptr || list_add_method == nullptr
        || evidence_class == nullptr || evidence_constructor == nullptr) {
        return false;
    }

    jstring type = env->NewStringUTF(evidence.type.c_str());
    if (type == nullptr || HasPendingJavaException(env)) {
        if (type != nullptr) {
            env->DeleteLocalRef(type);
        }
        return false;
    }

    jstring value = env->NewStringUTF(evidence.value.c_str());
    if (value == nullptr || HasPendingJavaException(env)) {
        env->DeleteLocalRef(type);
        if (value != nullptr) {
            env->DeleteLocalRef(value);
        }
        return false;
    }

    jstring description = env->NewStringUTF(evidence.description.c_str());
    if (description == nullptr || HasPendingJavaException(env)) {
        env->DeleteLocalRef(type);
        env->DeleteLocalRef(value);
        if (description != nullptr) {
            env->DeleteLocalRef(description);
        }
        return false;
    }

    jobject java_evidence = env->NewObject(
        evidence_class,
        evidence_constructor,
        type,
        value,
        description
    );

    if (java_evidence == nullptr || HasPendingJavaException(env)) {
        env->DeleteLocalRef(type);
        env->DeleteLocalRef(value);
        env->DeleteLocalRef(description);
        if (java_evidence != nullptr) {
            env->DeleteLocalRef(java_evidence);
        }
        return false;
    }

    env->CallBooleanMethod(evidence_list, list_add_method, java_evidence);
    const bool success = !HasPendingJavaException(env);

    env->DeleteLocalRef(java_evidence);
    env->DeleteLocalRef(description);
    env->DeleteLocalRef(value);
    env->DeleteLocalRef(type);

    return success;
} /* AppendJavaEvidence */

bool DroidProbe::Root::AppendJavaEvidences(JNIEnv* env, jobject evidence_list,
    const std::vector<NativeEvidence>& evidences) {
    if (env == nullptr || evidence_list == nullptr) {
        return false;
    }

    jclass list_class = env->GetObjectClass(evidence_list);
    if (list_class == nullptr || HasPendingJavaException(env)) {
        if (list_class != nullptr) {
            env->DeleteLocalRef(list_class);
        }
        return false;
    }

    jmethodID list_add_method = env->GetMethodID(
        list_class,
        "add",
        "(Ljava/lang/Object;)Z"
    );

    if (list_add_method == nullptr || HasPendingJavaException(env)) {
        env->DeleteLocalRef(list_class);
        return false;
    }

    jclass evidence_class = env->FindClass(kDetectionEvidenceClassName);
    if (evidence_class == nullptr || HasPendingJavaException(env)) {
        env->DeleteLocalRef(list_class);
        if (evidence_class != nullptr) {
            env->DeleteLocalRef(evidence_class);
        }
        return false;
    }

    jmethodID evidence_constructor = env->GetMethodID(
        evidence_class,
        "<init>",
        kDetectionEvidenceConstructorSignature
    );

    if (evidence_constructor == nullptr || HasPendingJavaException(env)) {
        env->DeleteLocalRef(evidence_class);
        env->DeleteLocalRef(list_class);
        return false;
    }

    bool success = true;
    for (const auto& evidence : evidences) {
        if (!AppendJavaEvidence(
            env,
            evidence_list,
            list_add_method,
            evidence_class,
            evidence_constructor,
            evidence)) {
            success = false;
            break;
        }
    }

    env->DeleteLocalRef(evidence_class);
    env->DeleteLocalRef(list_class);
    return success;
} /* AppendJavaEvidences */

DroidProbe::Root::ReadResult DroidProbe::Root::ReadTextFile(const char* path, size_t max_bytes) {
    ReadResult result;
    if (path == nullptr || max_bytes == 0U) {
        result.error_number = EINVAL;
        return result;
    }

    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        result.error_number = errno;
        return result;
    }
    result.opened = true;

    char buffer[kReadBufferSize];
    while (result.content.size() < max_bytes) {
        const size_t remaining = max_bytes - result.content.size();
        const size_t bytes_to_read = std::min(remaining, sizeof(buffer));
        const ssize_t count = read(fd, buffer, bytes_to_read);

        if (count == 0) {
            result.completed = true;
            break;
        }
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            result.error_number = errno;
            break;
        }

        result.content.append(buffer, static_cast<size_t>(count));
    } /* while */

    if (result.opened && !result.completed && result.error_number == 0
        && result.content.size() >= max_bytes) {
        // 达到读取上限时，不继续消耗资源；调用方应将该数据源标记为不完整。
        result.truncated = true;
    }

    close(fd);
    return result;
} /* ReadTextFile */


bool DroidProbe::Root::ReadTextFile(const char* path, std::string& out, size_t max_bytes) {
    return ReadTextFile(path, max_bytes).completed;
} /* ReadTextFile */

void DroidProbe::Root::AddEvidence(NativeScanResult& result, int score,
    const char* type, const std::string& value, const char* description) {
    if (type == nullptr || description == nullptr) {
        return;
    }

    for (const auto& existing : result.evidences) {
        // 发现重复条目
        if (existing.type == type && existing.value == value) {
            result.risk_score = std::max(result.risk_score, score);
            return;
        }
    }

    result.evidences.push_back(std::move(NativeEvidence{type, value, description}));
    result.risk_score = std::max(result.risk_score, score);
} /* AddEvidence */

void DroidProbe::Root::AddScanLimitation(NativeScanResult& result, const char* source,
    const char* reason) {
    result.state = NativeScanState::INCOMPLETE;
    AddEvidence(
        result,
        0,
        "SCAN_LIMITATION",
        source == nullptr ? "unknown" : source,
        reason == nullptr ? "检测数据源不可用" : reason
    );
} /* AddScanLimitation */

bool DroidProbe::Root::IsPermissionError(int error_number) {
    return error_number == EACCES || error_number == EPERM;
} /* IsPermissionError */

bool DroidProbe::Root::ParseKernelRelease(const char* release, int& major, int& minor) {
    if (release == nullptr) {
        return false;
    }

    major = -1;
    minor = -1;

    // sscanf 只关心最开始的 major.minor，不关心后面的 ABI / vendor 后缀。
    if (std::sscanf(release, "%d.%d", &major, &minor) != 2) {
        return false;
    }

    // 拒绝异常负版本，避免后续比较产生无意义结果。
    return major >= 0 && minor >= 0;
} /* ParseKernelRelease */

int DroidProbe::Root::CompareKernelVersion(int major, int minor, int other_major, int other_minor) {
    if (major != other_major) {
        return major < other_major ? -1 : 1;
    }

    if (minor != other_minor) {
        return minor < other_minor ? -1 : 1;
    }

    return 0;
} /* CompareKernelVersion */

int DroidProbe::Root::CheckPathExists(const char* path) {
    // 无路径参数时无法判断。
    if (path == nullptr) {
        return PathAccessResult::PathNotAccessible;
    }

    // access(F_OK) 只检查路径是否存在，不尝试读取、写入或执行文件。
    if (access(path, F_OK) == 0) {
        return PathAccessResult::PathExists;
    }

    // ENOENT 或 ENOTDIR 表示目标路径确实不存在。
    if (errno == ENOENT || errno == ENOTDIR) {
        return PathAccessResult::PathNotFound;
    }

    // 其他错误统一归类为不可确定，例如 EACCES / EPERM / EIO。
    return PathAccessResult::PathNotAccessible;
} /* CheckPathExists */

bool DroidProbe::Root::IsNumeric(const char* text) {
    // 空字符串不是合法数字。
    if (text == nullptr || *text == '\0') {
        return false;
    }

    for (const char* current = text; *current != '\0'; ++current) {
        if (!std::isdigit(static_cast<unsigned char>(*current))) {
            return false;
        }
    }

    return true;
} /* IsNumeric */

std::string DroidProbe::Root::Trim(const std::string& value) {
    size_t begin = 0;
    size_t end = value.size();

    while (begin < end && std::isspace(static_cast<unsigned char>(value[begin]))) {
        ++begin;
    }

    while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1]))) {
        --end;
    }

    return value.substr(begin, end - begin);
} /* Trim */

bool DroidProbe::Root::ReadProcessName(int pid, std::string& name) {
    // 优先读取 /proc/<pid>/comm，因为它只有极小的固定长度。
    const std::string path =
        std::string("/proc/") + std::to_string(pid) + "/comm";

    if (ReadTextFile(path.c_str(), name, 256)) {
        name = Trim(name);
        return !name.empty();
    }

    // comm 无法读取时，再尝试读取 cmdline 的 argv[0]。
    const std::string cmdline_path =
        std::string("/proc/") + std::to_string(pid) + "/cmdline";

    if (!ReadTextFile(cmdline_path.c_str(), name, 1024)) {
        return false;
    }

    const size_t nul = name.find('\0');
    if (nul != std::string::npos) {
        name.resize(nul);
    }

    name = Trim(name);
    return !name.empty();
} /* ReadProcessName */

jstring DroidProbe::Root::NewJavaString(JNIEnv* env, const std::string& value) {
    return NewJavaString(env, value.c_str());
} /* NewJavaString */

jstring DroidProbe::Root::NewJavaString(JNIEnv* env, const char* value) {
    if (env == nullptr) {
        return nullptr;
    }

    return env->NewStringUTF(value);
} /* NewJavaString */

jobjectArray DroidProbe::Root::NewStringArray(JNIEnv* env, jclass string_class,
                                              const std::vector<std::string>& values) {
    if (env == nullptr || string_class == nullptr) {
        return nullptr;
    }

    // 创建与证据数量相等的 String 数组。
    jobjectArray array = env->NewObjectArray(
        static_cast<jsize>(values.size()),
        string_class,
        nullptr
    );

    if (array == nullptr) {
        return nullptr;
    }

    // 将每条 Native 字符串转换成 Java String 并放入数组。
    for (jsize i = 0; i < static_cast<jsize>(values.size()); ++i) {
        jstring value = NewJavaString(env, values[static_cast<size_t>(i)]);

        if (value == nullptr) {
            // NewStringUTF 失败时释放已经创建的数组，让 Java 侧收到 null。
            env->DeleteLocalRef(array);
            return nullptr;
        }

        env->SetObjectArrayElement(array, i, value);
        env->DeleteLocalRef(value);

        // SetObjectArrayElement 本身可能产生 OutOfMemory 等 Java 异常。
        if (env->ExceptionCheck()) {
            env->DeleteLocalRef(array);
            return nullptr;
        }
    }

    return array;
} /* NewStringArray */
