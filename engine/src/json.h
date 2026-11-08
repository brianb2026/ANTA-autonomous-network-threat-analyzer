// Tiny streaming JSON writer for the newline-delimited IPC protocol.
// Handles comma placement and string escaping; no DOM.
#pragma once

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace anta {

class JsonWriter {
public:
    JsonWriter& begin_object() { sep(); out_ += '{'; first_.push_back(true); return *this; }
    JsonWriter& end_object() { out_ += '}'; first_.pop_back(); return *this; }
    JsonWriter& begin_array() { sep(); out_ += '['; first_.push_back(true); return *this; }
    JsonWriter& end_array() { out_ += ']'; first_.pop_back(); return *this; }

    JsonWriter& key(const char* k) {
        sep();
        string_lit(k);
        out_ += ':';
        pending_value_ = true;
        return *this;
    }

    JsonWriter& value(const std::string& s) { sep(); string_lit(s); return *this; }
    JsonWriter& value(const char* s) { sep(); string_lit(s); return *this; }
    JsonWriter& null_value() { sep(); out_ += "null"; return *this; }
    JsonWriter& value(bool b) { sep(); out_ += b ? "true" : "false"; return *this; }
    JsonWriter& value(int64_t v) { sep(); out_ += std::to_string(v); return *this; }
    JsonWriter& value(uint64_t v) { sep(); out_ += std::to_string(v); return *this; }
    JsonWriter& value(int v) { return value(static_cast<int64_t>(v)); }
    JsonWriter& value(unsigned v) { return value(static_cast<uint64_t>(v)); }
    JsonWriter& value(double v) {
        sep();
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%.6f", v);
        out_ += buf;
        return *this;
    }

    template <typename T>
    JsonWriter& kv(const char* k, const T& v) { key(k); return value(v); }

    const std::string& str() const { return out_; }

private:
    void sep() {
        if (pending_value_) { pending_value_ = false; return; }
        if (!first_.empty()) {
            if (!first_.back()) out_ += ',';
            first_.back() = false;
        }
    }

    // Length of a valid UTF-8 sequence starting at s[i] (0 if invalid: overlong,
    // surrogate, out of range or truncated). Wire data is arbitrary bytes.
    static size_t utf8_len(const std::string& s, size_t i) {
        auto b = [&](size_t k) { return static_cast<unsigned char>(s[k]); };
        unsigned char c = b(i);
        size_t n = c >= 0xF0 ? 4 : c >= 0xE0 ? 3 : c >= 0xC2 ? 2 : 0;
        if (n == 0 || c > 0xF4 || i + n > s.size()) return 0;
        for (size_t k = 1; k < n; ++k)
            if ((b(i + k) & 0xC0) != 0x80) return 0;
        if (n == 3 && ((c == 0xE0 && b(i + 1) < 0xA0) || (c == 0xED && b(i + 1) >= 0xA0))) return 0;
        if (n == 4 && ((c == 0xF0 && b(i + 1) < 0x90) || (c == 0xF4 && b(i + 1) >= 0x90))) return 0;
        return n;
    }

    void string_lit(const std::string& s) {
        out_ += '"';
        for (size_t i = 0; i < s.size(); ++i) {
            unsigned char c = static_cast<unsigned char>(s[i]);
            switch (c) {
                case '"': out_ += "\\\""; break;
                case '\\': out_ += "\\\\"; break;
                case '\n': out_ += "\\n"; break;
                case '\r': out_ += "\\r"; break;
                case '\t': out_ += "\\t"; break;
                default:
                    if (c >= 0x80) {
                        if (size_t n = utf8_len(s, i)) {  // valid UTF-8 passes through intact
                            out_.append(s, i, n);
                            i += n - 1;
                            break;
                        }
                    }
                    if (c < 0x20 || c >= 0x7F) {
                        // Control characters and invalid bytes are escaped one by one,
                        // so the output is always valid JSON.
                        char buf[8];
                        std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                        out_ += buf;
                    } else {
                        out_ += static_cast<char>(c);
                    }
            }
        }
        out_ += '"';
    }

    std::string out_;
    std::vector<bool> first_;
    bool pending_value_ = false;
};

}  // namespace anta
