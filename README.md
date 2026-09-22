# DroidProbe

DroidProbe 是一个用于检测 Android 设备运行环境、应用运行环境以及应用完整性状态的 Android Library。

本项目会从多个层面对设备和应用运行环境进行检测，包括：

- Root 与系统环境
- Magisk / KernelSU / APatch / Zygisk
- Frida / Xposed / LSPosed / Riru
- Debugger / Hook / Runtime Injection
- 模拟器与虚拟化环境
- Bootloader / Verified Boot / SELinux
- `/proc` / Process / Thread / Memory
- Native Library / ELF / Linker
- APK / DEX / Native Library 完整性
- 应用安装来源与重打包
- App Cloning / Virtualization
- VPN / Proxy 等网络环境
- Android Keystore / Key Attestation
- 其他可能影响应用安全性的环境信号

DroidProbe 作为一个 Library 对外提供统一的检测 API，示例 App 负责调用这些 API，并将检测结果展示出来。

---

## 核心设计

DroidProbe 的检测结果采用“信号 + 证据”的设计。

例如：

```text
Root
├── 状态：DETECTED
├── 风险等级：HIGH
└── 证据：
    ├── 发现 su
    ├── 检测到异常挂载
    └── 检测到异常系统属性
```

另一个检测项：

```text
Frida
├── 状态：NOT_DETECTED
├── 风险等级：NONE
└── 证据：
    └── 未发现已知 Frida 特征
```

对于当前 Android 版本不支持的检测：

```text
Key Attestation
├── 状态：NOT_SUPPORTED
└── 原因：
    └── 当前设备不具备所需能力
```

因此：

```text
检测失败
```

和：

```text
检测到异常
```

不会被混为一谈。

---

## 检测能力

### 1. Root 环境

#### 基础 Root 检测

- `su` 文件检测
- `su` 可执行性检测
- 常见 Root 路径检测
- Root Shell 检测
- Root 管理器检测
- `test-keys` 检测
- 系统属性检测
- 系统分区可写检测
- 挂载信息检测
- OverlayFS 检测

#### Root 框架

- Magisk 检测
- KernelSU 检测
- APatch 检测
- Zygisk 检测
- Root 隐藏相关特征检测

#### 辅助环境

- BusyBox 检测
- 异常系统目录检测
- Root 相关 Package 检测
- Root 相关进程检测

---

### 2. Runtime 环境

主要检测应用进程运行过程中是否存在调试、Hook、注入以及运行时修改环境。

#### Frida

- Frida 进程检测
- Frida 线程检测
- `/proc/self/maps` Frida 特征检测
- Frida Library 检测
- Frida 相关内存映射检测
- Frida 网络特征检测
- Native Frida 特征检测

#### Xposed / LSPosed / Riru

- Xposed 相关类检测
- Xposed Framework 特征检测
- LSPosed 特征检测
- Riru 特征检测
- 相关文件检测
- 相关 Library 检测
- Runtime 注入特征检测

#### Zygisk

- Zygisk 环境检测
- Zygisk 相关 Library 检测
- Zygote 注入特征检测

#### Debugger

- `Debug.isDebuggerConnected()` 检测
- `/proc/self/status` 检测
- `TracerPid` 检测
- Debugger 相关状态检测
- Native Debugger 检测

#### Hook

- 可疑 Library 检测
- Inline Hook 检测
- GOT Hook 检测
- PLT Hook 检测
- `.text` 完整性检测
- Runtime Injection 检测

---

### 3. Device 环境

用于检测设备本身的系统状态以及运行环境。

#### Emulator

- Build 信息检测
- 系统属性检测
- QEMU 特征检测
- 硬件信息检测
- CPU 信息检测
- GPU / OpenGL 特征检测
- 虚拟化特征检测
- 多信号模拟器检测

#### Bootloader

- Bootloader 状态检测
- Verified Boot 状态检测
- `ro.boot.*` 属性检测
- 系统启动状态检测

#### SELinux

- SELinux 状态检测
- Enforcing / Permissive / Disabled 判断
- SELinux 环境异常检测

#### ADB / Debug

- ADB 状态检测
- USB Debugging 检测
- Developer Options 检测

#### System

- Android 版本检测
- SDK Version 检测
- Security Patch Level 检测
- 系统属性检测
- 系统分区状态检测
- Kernel 信息检测

---

### 4. Application Environment

用于检测应用自身所处的运行环境。

#### App Cloning

- App Clone 检测
- 虚拟容器特征检测
- 应用数据目录异常检测
- UID / Process 环境异常检测
- ClassLoader 环境异常检测

#### Virtualization

- 虚拟化 Framework 特征检测
- 虚拟进程环境检测
- 文件系统环境异常检测
- 应用运行环境异常检测

---

### 5. Network Environment

用于检测应用当前所处的网络环境。

#### VPN

- VPN 状态检测
- VPN 网络接口检测
- VPN Transport 检测

#### Proxy

- HTTP Proxy 检测
- HTTPS Proxy 检测
- 系统代理检测
- 应用进程代理环境检测

#### 其他

- 网络接口检测
- 网络环境异常检测

> VPN 或 Proxy 本身并不意味着设备存在安全问题，因此网络检测结果应该作为环境信号，而不是直接作为最终安全结论。

---

### 6. Integrity

用于检测应用是否发生修改、重打包或者完整性变化。

#### APK

- APK 路径检测
- APK Hash 检测
- APK 文件完整性检测
- APK 签名检测
- 签名证书 SHA-256 检测
- 签名匹配检测

#### DEX

- DEX 文件检测
- DEX Hash 检测
- DEX CRC 检测
- DEX 文件数量检测
- DEX 完整性检测

#### Native Library

- Native Library Hash 检测
- Native Library 文件完整性检测

#### 安装来源

- Installer Package 检测
- 应用安装来源检测
- 非正常安装来源检测

#### 重打包

- ApplicationId 异常检测
- 签名变化检测
- APK 结构异常检测
- 重打包环境检测

---

### 7. Native

Native 模块主要研究 Android Native 层和 Linux 进程环境。

#### Process / Proc

- `/proc/self/status`
- `/proc/self/maps`
- `/proc/self/task`
- `/proc/mounts`
- Process 信息检测
- Thread 信息检测

#### Memory

- Memory Mapping 检测
- 可执行匿名内存检测
- `rwx` Memory Region 检测
- `memfd` 检测
- 可疑 Memory Region 检测
- Library Mapping 检测

#### Linker

- 已加载 Native Library 枚举
- Dynamic Linker 信息检测
- 可疑 Library 路径检测
- Library 加载环境检测

#### ELF

- ELF Header 检测
- Program Header 检测
- Section 信息检测
- Dynamic Section 检测
- Symbol 信息检测
- ELF 完整性检测

#### Native Integrity

- `.text` 完整性检测
- GOT 完整性检测
- PLT 完整性检测
- Native Library 完整性检测
- 关键模块完整性检测

#### Syscall

- Native System Call
- 关键系统调用检测
- 系统调用结果异常检测

---

### 8. Hardware / Attestation

用于研究 Android 设备硬件支持的完整性证明能力。

#### Android Keystore

- Android Keystore 检测
- KeyMint / Keystore 环境检测
- TEE 检测
- StrongBox 检测

#### Key Attestation

- Key Attestation
- Attestation Certificate 获取
- X.509 Certificate 解析
- Attestation Record 解析
- Root Of Trust 信息解析
- Device Locked 状态解析
- Verified Boot 状态解析
- Hardware-backed Security Level 检测

---

## 统一 API

DroidProbe 最终希望向调用方提供统一的 API。

例如：

```java
EnvironmentReport report = DroidProbe.scan(context);
```

而不是要求调用方分别处理：

```text
RootDetector
FridaDetector
EmulatorDetector
XposedDetector
...
```

最终统一返回：

```text
EnvironmentReport
│
├── RootResult
├── RuntimeResult
├── DeviceResult
├── ApplicationResult
├── NetworkResult
├── IntegrityResult
├── NativeResult
└── AttestationResult
```

---

## Detector 设计

每一个检测能力尽量独立实现。

例如：

```text
RootDetector
FridaDetector
EmulatorDetector
BootloaderDetector
ElfDetector
```

检测器之间尽量减少直接依赖。

可以抽象为：

```text
Detector
    │
    ├── check()
    │
    └── DetectionResult
```

---

## Detection Status

DroidProbe 不简单使用 `true / false` 表示所有检测结果。

计划使用：

```text
DETECTED
NOT_DETECTED
NOT_SUPPORTED
ERROR
UNKNOWN
```

例如：

```text
Frida
├── status: DETECTED
├── evidence:
│   ├── suspicious library
│   └── suspicious memory mapping
└── riskLevel: HIGH
```

或者：

```text
Key Attestation
├── status: NOT_SUPPORTED
└── reason:
    └── 当前设备不支持所需能力
```

---

## 风险等级

DroidProbe 的检测结果可以提供风险等级作为辅助信息。

计划：

```text
NONE
LOW
MEDIUM
HIGH
CRITICAL
```

风险等级只是检测模块对当前信号的描述，并不代表 DroidProbe 对整个设备最终安全性的判断。

---

## 多信号检测

DroidProbe 不会依赖单一特征作为最终判断依据。

例如：

```text
su
test-keys
overlayfs
异常 mount
异常 property
```

应该被视为不同的 Root 相关信号。

检测流程类似：

```text
                  Root Detection
                        │
       ┌────────────────┼────────────────┐
       ▼                ▼                ▼
   File Check      Property Check    Mount Check
       │                │                │
       └────────────────┼────────────────┘
                        ▼
                  Detection Result
```

Frida、模拟器、Hook、应用克隆等检测同样采用类似思路。

---

## 项目结构

DroidProbe 核心 Library 计划采用模块化结构：

```text
DroidProbe
│
├── core
│   ├── DroidProbe
│   ├── Detector
│   ├── DetectionResult
│   ├── EnvironmentReport
│   └── DetectionStatus
│
├── root
│   ├── SuDetector
│   ├── RootAppDetector
│   ├── MagiskDetector
│   ├── KernelSuDetector
│   ├── APatchDetector
│   ├── BusyBoxDetector
│   ├── MountDetector
│   └── RootPropertyDetector
│
├── runtime
│   ├── FridaDetector
│   ├── XposedDetector
│   ├── ZygiskDetector
│   ├── RiruDetector
│   ├── DebuggerDetector
│   └── HookDetector
│
├── device
│   ├── EmulatorDetector
│   ├── BootloaderDetector
│   ├── SelinuxDetector
│   ├── AdbDetector
│   ├── DeveloperOptionsDetector
│   └── SecurityPatchDetector
│
├── environment
│   ├── AppCloningDetector
│   └── VirtualizationDetector
│
├── network
│   ├── VpnDetector
│   └── ProxyDetector
│
├── integrity
│   ├── SignatureDetector
│   ├── ApkIntegrityDetector
│   ├── DexIntegrityDetector
│   ├── InstallerDetector
│   └── RepackagingDetector
│
├── native
│   ├── ProcDetector
│   ├── ProcessDetector
│   ├── MapsDetector
│   ├── MemoryDetector
│   ├── LinkerDetector
│   ├── ElfDetector
│   ├── SyscallDetector
│   └── NativeIntegrityDetector
│
└── attestation
    ├── KeyStoreDetector
    ├── KeyAttestationDetector
    ├── TeeDetector
    └── StrongBoxDetector
```

---

## Java / JNI / Native

DroidProbe 会根据检测目标选择合适的实现方式。

简单的 Android Framework 信息：

```text
Java
    ↓
Android Framework
```

需要访问 Native 或 Linux 环境的信息：

```text
Java
    ↓
JNI
    ↓
C/C++
    ↓
Android Native / Linux
```

更底层的检测可能涉及：

```text
/proc
syscall
linker
ELF
memory mapping
```

并不是所有检测都需要使用 JNI。

能够使用公开 Android API 完成的检测，优先使用公开 API。

只有在确实需要更底层信息时再进入 Native 层。

---

## 已知限制

Android 不同版本之间存在明显差异。

同时，不同厂商 ROM 也可能对：

- Framework
- SELinux
- `/proc`
- 系统属性
- Native Library
- Keystore
- Bootloader

进行不同程度的修改。

因此 DroidProbe 的检测结果不保证在所有设备上都具有完全一致的行为。

某些检测方法可能存在：

```text
误报
漏报
权限限制
版本限制
厂商差异
```

因此项目会尽量记录检测证据，而不是只输出最终布尔值。

不同厂商的系统得出的结果可能是不一样的，这个项目是根据 LineageOS 来完成的。

输出的结果可能随着这些厂商修改的情况而不同，后续可能加入对不同厂商的适配。

---

## 免责声明

DroidProbe 是一个用于 Android 安全研究、学习和开发的开源项目。

项目中的检测能力主要用于研究 Android 设备运行环境、应用运行时状态以及应用完整性。

检测结果不代表对设备安全性的绝对判断。
