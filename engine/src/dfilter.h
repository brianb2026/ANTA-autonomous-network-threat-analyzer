// Wireshark-style display filters ("ip.addr == 10.0.0.0/8 && tcp.port == 443")
// over the fields the packet decoder records for each frame.
//
// Semantics follow Wireshark: a bare field or protocol tests presence; "=="
// matches if any occurrence matches, "!=" only if all occurrences differ; any
// comparison against a field the frame doesn't have is false.
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace anta {

struct FieldValue {
    enum Type : uint8_t { kUint, kInt, kDouble, kString, kIPv4, kIPv6, kMac, kBytes, kNone };
    Type type = kNone;
    uint64_t u = 0;   // kUint (booleans are 0/1), kInt (two's complement)
    double d = 0;     // kDouble
    std::string s;    // text for kString; raw bytes for kIPv4 (4), kIPv6 (16), kMac (6), kBytes
};

// The fields and protocols one frame contains, named as Wireshark names them.
class FrameFields {
public:
    struct Field {
        const char* name;  // always a string literal
        FieldValue value;
    };
    struct Proto {
        const char* name;
        uint32_t offset, length;  // the layer's bytes within the frame
    };

    void clear() {
        fields.clear();
        protos.clear();
        outer_fields = outer_protos = static_cast<size_t>(-1);
    }
    void proto(const char* name, size_t offset, size_t length);
    void uint(const char* name, uint64_t v);
    void sint(const char* name, int64_t v);
    void boolean(const char* name, bool v) { uint(name, v ? 1 : 0); }
    void real(const char* name, double v);
    void string(const char* name, std::string v);
    void ipv4(const char* name, const uint8_t* a);
    void ipv6(const char* name, const uint8_t* a);
    void mac(const char* name, const uint8_t* a);
    void bytes(const char* name, const uint8_t* p, size_t n);

    struct Mark {
        size_t fields, protos;
    };
    Mark mark() const { return {fields.size(), protos.size()}; }
    void rollback(Mark m) {
        if (fields.size() > m.fields) fields.resize(m.fields);
        if (protos.size() > m.protos) protos.resize(m.protos);
        if (outer_fields > fields.size() || outer_protos > protos.size())
            outer_fields = outer_protos = static_cast<size_t>(-1);
    }

    bool has_proto(const char* name) const;
    const FieldValue* first(const char* name) const;

    // Where the packet quoted inside an ICMP error begins (Wireshark decodes it,
    // so filters see its fields, but statistics only count the outer packet).
    void begin_error_packet() {
        if (outer_fields == static_cast<size_t>(-1)) {
            outer_fields = fields.size();
            outer_protos = protos.size();
        }
    }
    bool has_outer_proto(const char* name) const;
    const FieldValue* first_outer(const char* name) const;
    size_t outer_fields = static_cast<size_t>(-1), outer_protos = static_cast<size_t>(-1);
    std::string protocols() const;  // "eth:ethertype:ip:tcp:tls", like frame.protocols

    std::vector<Field> fields;
    std::vector<Proto> protos;
    const uint8_t* frame = nullptr;
    size_t frame_len = 0;
};

class DisplayFilter {
public:
    // nullptr and a message (in Wireshark's wording where it has one) on error.
    static std::unique_ptr<DisplayFilter> compile(const std::string& text, std::string& error);
    ~DisplayFilter();
    bool match(const FrameFields& frame) const;

    struct Node;

private:
    DisplayFilter() = default;
    static std::unique_ptr<DisplayFilter> compile_unchecked(const std::string& text, std::string& error);
    std::unique_ptr<Node> root_;
};

// A field value written the way a filter would compare it ("10.0.0.1", "\"GET\"", "443").
std::string filter_literal(const FieldValue& v);

// Every field and protocol name a filter may use (Wireshark's names), as
// "name\ttype\tdescription" lines, for the UI's completion list.
std::vector<std::string> filter_field_catalog();

}  // namespace anta
