#include <cassert>
#include <cstdint>

extern "C" int secrev_can_access(int role_level, int required_priority);
extern "C" int secrev_analyze_text(const char* text, int* word_count, int* email_count, int* number_count);
extern "C" int secrev_scan_text(const char* text, int* finding_count, std::uint32_t* finding_flags);
extern "C" int secrev_count_matches(const char* text, const char* query, int* match_count);

int main() {
    assert(secrev_can_access(0, 0) == 1);
    assert(secrev_can_access(0, 2) == 0);
    assert(secrev_can_access(2, 1) == 1);
    assert(secrev_can_access(-1, 0) == 0);
    assert(secrev_can_access(2, 3) == 0);

    int words = 0;
    int emails = 0;
    int numbers = 0;
    assert(secrev_analyze_text("Contact sam@example.org, case 123-45.", &words, &emails, &numbers) == 1);
    assert(words == 7);
    assert(emails == 1);
    assert(numbers == 2);
    assert(secrev_analyze_text(nullptr, &words, &emails, &numbers) == 0);
    assert(secrev_analyze_text("text", nullptr, &emails, &numbers) == 0);

    int findings = 0;
    std::uint32_t flags = 0;
    assert(secrev_scan_text("<SCRIPT> and javascript:", &findings, &flags) == 1);
    assert(findings == 2);
    assert(flags != 0);
    assert(secrev_scan_text("ordinary document", &findings, &flags) == 1);
    assert(findings == 0 && flags == 0);
    assert(secrev_scan_text(nullptr, &findings, &flags) == 0);

    int matches = 0;
    assert(secrev_count_matches("Review review reviewed", "review", &matches) == 1);
    assert(matches == 3);
    assert(secrev_count_matches("review", "", &matches) == 0);
    return 0;
}
