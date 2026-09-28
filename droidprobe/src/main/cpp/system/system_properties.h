//
// Created by ignite on 9/23/26.
//

#ifndef DROIDPROBE_SYSTEM_PROPERTIES_H
#define DROIDPROBE_SYSTEM_PROPERTIES_H

#include <string>

namespace DroidProbe {
    namespace System {
        std::string get_system_property(const char *key);
    } // namespace System
} // namespace DroidProbe

#endif // DROIDPROBE_SYSTEM_PROPERTIES_H
