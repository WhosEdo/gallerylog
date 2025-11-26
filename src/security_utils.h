// security_utils.{h,cpp}
// -------------------------------------
// Shared security and filesystem utilities for the secure gallery log.
// declarations of security util functions

#ifndef SECURITY_UTILS_H
#define SECURITY_UTILS_H

#include <string>
#include <vector>

// Tokens & Authentication

enum class Operation { Read , Append};
enum class Permission { ReadOnly , AppendOnly , ReadWrite};

struct UserTokenInfo {
    std::string actorId; // ID of user
    Permission permission; // ReadOnly | AppendOnly | ReadWrite
    std::string tokenHash; // hash of user's token
};


std::string sha256Hex(const std::string& s); // hashing tokens
bool constantTimeEquals(const std::string& a, const std::string& b); //compare hashes

const std::vector<UserTokenInfo>& getBuiltInTokenStore(); // retrieves data of all stored tokens
bool permissionAllows(Permission p, Operation op); // checks if user permission allows use of selected operation

const UserTokenInfo* authenticateToken(const std::string& providedToken, 
    Operation requiredOp, const std::vector<UserTokenInfo>& store);

// Represents a single validated log entry in memory.
// Matches on-disk format: timestamp|actorId|personId|action|roomId
struct LogEntry {
    std::string timestamp; // Unix epoch as string
    std::string actorId;   // who appended (from authenticated token)
    std::string personId;  // subject of the event
    std::string action;    // ENTER | MOVE | EXIT
    std::string roomId;    // room name or "-" for EXIT
};

// Validation helpers
bool validateAction(const std::string& action);
bool validateRoomId(const std::string& room);
bool validatePersonId(const std::string& id);
bool validateTimestamp(const std::string& ts);

// Log formatting & parsing
std::string formatLogEntry(const LogEntry& e);
bool parseLogLine(const std::string& line, LogEntry& out);

// Error reporting
void printSecureError(const std::string& msg);

// File open + locking
inline const std::string LOG_FILE_PATH = "logs/gallery.log";
int  openFileRO(const std::string& path);      // open read-only, return fd or -1
int  openFileAppend(const std::string& path);  // open append-only, 0600 perms
bool lockFile(int fd, bool exclusive);         // true = LOCK_EX, false = LOCK_SH
void unlockFile(int fd);
#endif // SECURITY_UTILS_H