#include <cstddef>
#include <cstdint>

namespace {
constexpr std::size_t kMaxTextBytes = 8 * 1024 * 1024;

std::size_t bounded_length(const char* value) {
    if (value == nullptr) {
        return kMaxTextBytes + 1;
    }
    std::size_t length = 0;
    while (length <= kMaxTextBytes && value[length] != '\0') {
        ++length;
    }
    return length;
}

unsigned char ascii_lower(unsigned char value) {
    return value >= 'A' && value <= 'Z' ? static_cast<unsigned char>(value + ('a' - 'A')) : value;
}

bool contains_ascii_case_insensitive(const char* text, std::size_t length, const char* pattern) {
    std::size_t pattern_length = 0;
    while (pattern[pattern_length] != '\0') {
        ++pattern_length;
    }
    if (pattern_length == 0 || pattern_length > length) {
        return false;
    }
    for (std::size_t start = 0; start <= length - pattern_length; ++start) {
        std::size_t offset = 0;
        while (offset < pattern_length && ascii_lower(static_cast<unsigned char>(text[start + offset])) ==
               ascii_lower(static_cast<unsigned char>(pattern[offset]))) {
            ++offset;
        }
        if (offset == pattern_length) {
            return true;
        }
    }
    return false;
}
}

#if defined(_WIN32)
#define SECREV_API extern "C" __declspec(dllexport)
#else
#define SECREV_API extern "C" __attribute__((visibility("default")))
#endif

// Small, deterministic native core. The managed layer owns storage and cryptography.
SECREV_API int secrev_can_access(int role_level, int required_priority) {
    if (role_level < 0 || role_level > 2 || required_priority < 0 || required_priority > 2) {
        return 0;
    }
    return role_level >= required_priority ? 1 : 0;
}

SECREV_API int secrev_analyze_text(const char* text, int* word_count, int* email_count, int* number_count) {
    const std::size_t text_length = bounded_length(text);
    if (text_length > kMaxTextBytes || word_count == nullptr || email_count == nullptr || number_count == nullptr) {
        return 0;
    }

    *word_count = 0;
    *email_count = 0;
    *number_count = 0;

    bool in_word = false;
    bool in_number = false;
    bool in_email = false;
    bool email_has_at = false;
    bool email_has_dot_after_at = false;
    std::size_t email_length = 0;

    for (const unsigned char* cursor = reinterpret_cast<const unsigned char*>(text); *cursor != '\0'; ++cursor) {
        const unsigned char ch = *cursor;
        const bool word_character = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch >= 0x80;
        if (word_character && !in_word) {
            ++(*word_count);
        }
        in_word = word_character;

        const bool digit = ch >= '0' && ch <= '9';
        if (digit && !in_number) {
            ++(*number_count);
        }
        in_number = digit;

        const bool email_character = ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || digit || ch == '.' || ch == '_' || ch == '%' || ch == '+' || ch == '-' || ch == '@');
        if (email_character) {
            if (!in_email) {
                in_email = true;
                email_has_at = false;
                email_has_dot_after_at = false;
                email_length = 0;
            }
            ++email_length;
            if (ch == '@' && !email_has_at) {
                email_has_at = true;
            } else if (ch == '.' && email_has_at) {
                email_has_dot_after_at = true;
            }
        } else if (in_email) {
            if (email_has_at && email_has_dot_after_at && email_length >= 6) {
                ++(*email_count);
            }
            in_email = false;
        }
    }

    if (in_email && email_has_at && email_has_dot_after_at && email_length >= 6) {
        ++(*email_count);
    }
    return 1;
}

// Defensive signature scan only. It never executes or interprets document data.
SECREV_API int secrev_scan_text(const char* text, int* finding_count, std::uint32_t* finding_flags) {
    const std::size_t text_length = bounded_length(text);
    if (text_length > kMaxTextBytes || finding_count == nullptr || finding_flags == nullptr) {
        return 0;
    }

    static const char* signatures[] = {
        "<script", "javascript:", "powershell", "cmd.exe", "eval(", "onerror=", "onload="
    };
    *finding_count = 0;
    *finding_flags = 0;
    for (std::size_t i = 0; i < sizeof(signatures) / sizeof(signatures[0]); ++i) {
        if (contains_ascii_case_insensitive(text, text_length, signatures[i])) {
            ++(*finding_count);
            *finding_flags |= static_cast<std::uint32_t>(1u << i);
        }
    }
    return 1;
}

SECREV_API int secrev_count_matches(const char* text, const char* query, int* match_count) {
    const std::size_t text_length = bounded_length(text);
    const std::size_t query_length = bounded_length(query);
    if (text_length > kMaxTextBytes || query_length == 0 || query_length > 256 || match_count == nullptr) {
        return 0;
    }

    *match_count = 0;
    if (query_length > text_length) {
        return 1;
    }
    for (std::size_t start = 0; start <= text_length - query_length;) {
        std::size_t offset = 0;
        while (offset < query_length && ascii_lower(static_cast<unsigned char>(text[start + offset])) ==
               ascii_lower(static_cast<unsigned char>(query[offset]))) {
            ++offset;
        }
        if (offset == query_length) {
            ++(*match_count);
            start += query_length;
        } else {
            ++start;
        }
    }
    return 1;
}
