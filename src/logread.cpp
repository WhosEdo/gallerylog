// logread.cpp
// -------------------------------------
// authenticated read-only tool for the secure gallery log.
//
// responsibilities:
// authenticate token with proper permissions, READ
// open fixed log file, read only
// acquire shared read file lock
// parse each line to build each log entry
// print parsed entries
// never modifies log, only reads

#include "security_utils.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <cerrno>   // errno
#include <cstring>  // strerror
#include <unistd.h> 

int main(int argc, char* argv[]) {
    //   ./logread -T <token> <logpath>
     if (argc != 3 || std::string(argv[1]) != "-T") {
        std::cerr << "Usage: " << argv[0] << " -T <token>\n";
        return 2; // argument error
    }

    std::string token   = argv[2];
    std::string logPath = LOG_FILE_PATH;

    // Authenticate token for READ operation.
    const auto& store = getBuiltInTokenStore();
    const UserTokenInfo* user =
        authenticateToken(token, Operation::Read, store);

    if (!user) {
        printSecureError("authentication failed");
        return 1;
    }

    // Open the log file (read-only).
    int fd = openFileRO(logPath);
    if (fd < 0) {
        // If file doesn't exist yet, treat as empty log/state.
        if (errno == ENOENT) {
            std::cout << "No log file found at '" << logPath
                      << "'. Assuming empty gallery state.\n";
            return 0; // not an error; just no events yet
        }

        // Any other error is a real failure.
        printSecureError("failed to open log file for reading");
        return 1;
    }

     std::cout << "Accessing log file..." << std::endl;

    // Acquire shared (reader) lock.
    if (!lockFile(fd, false)) {
        printSecureError("failed to acquire shared read lock on log file");
        ::close(fd);
        return 1;
    }

    // Use an input stream to read lines.
    std::ifstream in(logPath);
    if (!in.is_open()) {
        printSecureError("failed to open input stream for log file");
        unlockFile(fd);
        ::close(fd);
        return 1;
    }

    std::vector<LogEntry> entries;
    std::string line;

    // Read file line by line and parse into LogEntry.
    while (std::getline(in, line)) {
        LogEntry e;
        if (parseLogLine(line, e)) {
            entries.push_back(e);
        } else {
            // Malformed lines are treated as untrusted and skipped.
        }
    }

     in.close();
    unlockFile(fd);
    ::close(fd);

    if (entries.empty()) {
        std::cout << "Log file exists but contains no valid entries.\n";
        return 0;
    }

    std::cout << "Parsed " << entries.size() << " log entries:\n";
    for (const auto& e : entries) {
        // print out log entries
        std::cout << e.timestamp << " | "
                  << e.actorId   << " | "
                  << e.personId  << " | "
                  << e.action    << " | "
                  << e.roomId    << "\n";
    }

    return 0;
}