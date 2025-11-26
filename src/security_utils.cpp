// security_utils.{h,cpp}
// -------------------------------------
// shared security and filesystem utilities for the secure gallery log.
// 
// responsibilities:
// token hashing using SHA-256
// token store with roles and permissions
// permession checks, READ and APPEND
// input validation for rooms, person and guess IDs, and events
// log entry formatting and parsing
// secure file open, append, and locking to perform actions
// 
// logread and logappend both use helpers

#include "security_utils.h"
#include <openssl/sha.h>
#include <vector>
#include <string>
#include <cctype>          // std::isalnum
#include <unordered_set>   // room whitelist
#include <sys/file.h>      // flock
#include <sys/stat.h>      // file modes
#include <fcntl.h>         // open flags
#include <unistd.h>        // open/close
#include <iostream>        // printSecureError
#include <cstdio>          // FILE*, fprintf

// convert raw bytes -> loewcase hex string
static std::string toHex(const unsigned char* data, size_t len) {
    static const char* HEX = "0123456789abcdef";
    std::string out; out.resize(len * 2); // pre-allocate output buffer

    //convert each byte into 2 hex characters
    for (size_t i = 0; i < len; ++i) {
        unsigned char b = data[i];
        out[2*i] = HEX[(b >> 4) & 0x0F];
        out[2*i+1] = HEX[b & 0x0F];
    }
    return out;
}

// Computes SHA-256 hash of token and converts to hex representation
std::string sha256Hex(const std::string& s) {
    unsigned char digest[SHA256_DIGEST_LENGTH]; // digest the hashing data into hex

    SHA256_CTX ctx; // hashing context (internal state)
    SHA256_Init(&ctx); // start hashing
    SHA256_Update(&ctx, s.data(), s.size()); // feed input bytes
    SHA256_Final(digest, &ctx); // finalize hash into digest

    return toHex(digest, SHA256_DIGEST_LENGTH); // return hex represenatation
}

bool constantTimeEquals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;

    unsigned char diff = 0;

    // XOR every character so timing is identical regardless of mismatch position
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= (unsigned char)(a[i] ^ b[i]);
    }
    return diff == 0; // Only equal if XOR of all bytes is zero
}

// Store of user's tokens and their permissions
// hash value, actual password not hardcoded
static const std::vector<UserTokenInfo> BUILT_IN_STORE = {
    {"guard_alex",  Permission::AppendOnly, "e45703ec0bf6e9b29fec9e4819f33c7c8a302d93eccef0f7bddd57c80c93f5a0"},
    {"manager_kim", Permission::ReadOnly,   "12ae512c7eeda74af4e625e1fe2888645c434586d24b75ea3302d3d75d121130"},
    {"admin_lee",   Permission::ReadWrite,  "f929608275fa3fa111110583af685764f71a1ddc67dd2af65284e35eceb583ad"}
};

// Returns the built-in hash table of authorized users.
const std::vector<UserTokenInfo>& getBuiltInTokenStore() {
    return BUILT_IN_STORE;
}

// Defines which permissions allow which operations.
bool permissionAllows(Permission p, Operation op) {
    if (p == Permission::ReadWrite) return true;            // Admin
    if (p == Permission::ReadOnly)  return op == Operation::Read;
    if (p == Permission::AppendOnly)return op == Operation::Append;
    return false;
}

// Verifies:
//  1. The plaintext token matches a stored hash
//  2. The matched user has permission for the requested operation
//
// Returns pointer to the user record on success, or nullptr on failure.
const UserTokenInfo* authenticateToken(const std::string& providedToken,
                                       Operation requiredOp,
                                       const std::vector<UserTokenInfo>& store) {
    if (providedToken.empty())
        return nullptr;  // Empty tokens are automatically invalid

    // Hash user's provided plaintext token
    const std::string providedHash = sha256Hex(providedToken);

    // Scan all known users
    for (const auto& user : store) {

        // Compare digest using constant-time comparison
        if (constantTimeEquals(providedHash, user.tokenHash)) {

            // Found matching user — now check permissions
            if (permissionAllows(user.permission, requiredOp)) {
                return &user; // authenticated + authorized
            }

            return nullptr; // correct token, wrong permission
        }
    }

    return nullptr; // No matching token found
}

// Used for actorId and personId.
static bool validIdLike(const std::string& s) {
    if (s.empty() || s.size() > 32) return false;   // enforce size bound

    for (char c : s) {
        // allowed: letters, digits, underscore, dash
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-')) {
            return false;
        }
    }
    return true;
}

// Only allow the 3 valid actions we support.
bool validateAction(const std::string& action) {
    return (action == "ENTER" ||
            action == "MOVE"  ||
            action == "EXIT");
}

// allows valid rooms in the gallery
bool validateRoomId(const std::string& room) {
    static const std::unordered_set<std::string> ROOMS = {
        "lobby",
        "gallery1",
        "gallery2",
        "vault",
        "security",
        "storage",
        "-"        // used for EXIT events
    };

    return ROOMS.find(room) != ROOMS.end();
}

// Validate person ID (guest/employee IDs).
bool validatePersonId(const std::string& id) {
    return validIdLike(id);
}

// Validate timestamp parsed from log file.
bool validateTimestamp(const std::string& ts) {
    if (ts.empty() || ts.size() > 11) return false; // 10–11 digits typical for epoch

    for (char c : ts) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            return false;
        }
    }
    return true;
}

// Simple splitter by a single character delimiter.
static std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> out;
    std::string cur;

    for (char c : s) {
        if (c == delim) {
            out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    out.push_back(cur);
    return out;
}

// Produce the canonical on-disk log format for one entry:
// timestamp|actorId|personId|action|roomId\n
std::string formatLogEntry(const LogEntry& e) {
    std::string line;

    line.reserve(e.timestamp.size() +
                 e.actorId.size() +
                 e.personId.size() +
                 e.action.size() +
                 e.roomId.size() +
                 5); // 4 '|' + '\n'

    line.append(e.timestamp);
    line.push_back('|');
    line.append(e.actorId);
    line.push_back('|');
    line.append(e.personId);
    line.push_back('|');
    line.append(e.action);
    line.push_back('|');
    line.append(e.roomId);
    line.push_back('\n');

    return line;
}

// Parse a single line from the log file into a LogEntry.
// Returns true if the line is well-formed and passes validation.
bool parseLogLine(const std::string& line, LogEntry& out) {
    // Make a copy so we can strip newline characters.
    std::string s = line;

    // Trim trailing \r and \n (handles Windows + Unix newlines).
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) {
        s.pop_back();
    }

    auto parts = split(s, '|');
    if (parts.size() != 5) {
        return false; // wrong number of fields
    }

    const std::string& ts   = parts[0];
    const std::string& aid  = parts[1];
    const std::string& pid  = parts[2];
    const std::string& act  = parts[3];
    const std::string& room = parts[4];

    // Validate each field independently.
    if (!validateTimestamp(ts))   return false;
    if (!validIdLike(aid))        return false; // actorId uses same rules as IDs
    if (!validatePersonId(pid))   return false;
    if (!validateAction(act))     return false;
    if (!validateRoomId(room))    return false;

    // Fill the output struct.
    out.timestamp = ts;
    out.actorId   = aid;
    out.personId  = pid;
    out.action    = act;
    out.roomId    = room;

    return true;
}

// Print a generic error message.
// Does NOT leak sensitive info such as file paths or tokens.
void printSecureError(const std::string& msg) {
    std::cerr << "[error] " << msg << "\n";
}

// Open file in read-only mode.
// Returns fd >= 0 on success, or -1 on error.
int openFileRO(const std::string& path) {
    int fd = ::open(path.c_str(), O_RDONLY);
    return fd; // caller will check for -1
}

// Open file for append-only writes, creating it if necessary.
// Permissions: 0600 (owner read/write only).
int openFileAppend(const std::string& path) {
    int fd = ::open(path.c_str(),
                    O_WRONLY | O_CREAT | O_APPEND,
                    0600); // owner rw, no permissions for others
    return fd;
}

// Acquire a file lock using flock().
// exclusive = true  -> LOCK_EX (writer lock)
// exclusive = false -> LOCK_SH (shared reader lock)
//
// Returns true on success, false on failure.
bool lockFile(int fd, bool exclusive) {
    if (fd < 0) return false;

    int op = exclusive ? LOCK_EX : LOCK_SH;
    if (::flock(fd, op) != 0) {
        return false;
    }
    return true;
}

// Release a file lock previously acquired with lockFile().
void unlockFile(int fd) {
    if (fd >= 0) {
        (void)::flock(fd, LOCK_UN);
    }
}