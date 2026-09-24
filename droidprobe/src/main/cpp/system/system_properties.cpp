//
// Created by ignite on 9/23/26.
//

#include "system_properties.h"

#include <sys/system_properties.h>

std::string DroidProbe::get_system_property(const char* key) {
    if (key == nullptr) {
        return {};
    }

    char value[PROP_VALUE_MAX]{};

    int length = __system_property_get(key, value);

    if (length <= 0) {
        return {};
    }

    return {value, static_cast<size_t>(length)};
}
