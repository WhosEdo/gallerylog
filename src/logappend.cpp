// logappend.cpp
// -------------------------------------
// Authenticated append-only writer for the secure gallery log.
//
// authenticate token with APPEND permission
// open fixed log path in append-only
// acquire exclusive file lock
// reconstruct state for each person by parsing log entries
// enforce gallery rules
//      ENTER: only if person is not inside; room must be real (not "-")
//      MOVE:  only if person is inside; new room != current; not "-"
//      EXIT:  only if person is inside; room must be "-" or current room
// format and append new log entry
// never modify or delete existing log

#include "security_utils.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <unordered_map>
#include <cerrno>
#include <cstring>
#include <unistd.h>
#include <chrono>

// Helper function to get current timestamp as string
std::string getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    return std::to_string(time_t);
}

// Simple struct to track current state of a person
struct PersonState {
    bool inside = false;
    std::string room; // last known room (if inside)
};

int main(int argc, char* argv[]) {
    // ./logappend -T <token> -E <event> -P <personId> -R <roomId>
    if (argc != 9) {
        std::cerr << "Usage: " << argv[0]
                  << " -T <token> -E <event> -P <personId> -R <roomId>\n";
        std::cerr << "Valid events: ENTER, MOVE, EXIT\n";
        std::cerr << "Valid rooms: lobby, gallery1, gallery2, vault, security, storage, -\n";
        return 2;
    }

    std::string token, event, personId, roomId;

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-T" && i + 1 < argc) {
            token = argv[++i];
        } else if (arg == "-E" && i + 1 < argc) {
            event = argv[++i];
        } else if (arg == "-P" && i + 1 < argc) {
            personId = argv[++i];
        } else if (arg == "-R" && i + 1 < argc) {
            roomId = argv[++i];
        }
    }

    // Validate required parameters
    if (token.empty() || event.empty() || personId.empty() || roomId.empty()) {
        std::cerr << "Error: All parameters (-T, -E, -P, -R) are required\n";
        return 2;
    }

    // Validate event and room ID format
    if (!validateAction(event)) {
        std::cerr << "Error: Invalid event '" << event
                  << "'. Must be ENTER, MOVE, or EXIT\n";
        return 2;
    }

    if (!validateRoomId(roomId)) {
        std::cerr << "Error: Invalid room ID '" << roomId << "'\n";
        return 2;
    }

    if (!validatePersonId(personId)) {
        std::cerr << "Error: Invalid person ID '" << personId << "'\n";
        return 2;
    }

    // Authenticate token for APPEND operation
    const auto& store = getBuiltInTokenStore();
    const UserTokenInfo* user =
        authenticateToken(token, Operation::Append, store);

    if (!user) {
        printSecureError("authentication failed");
        return 1;
    }

    std::string logPath = LOG_FILE_PATH;

    // Open the log file for appending (creates with 0600 perms if needed)
    int fd = openFileAppend(logPath);
    if (fd < 0) {
        printSecureError("failed to open log file for appending");
        return 1;
    }

    // Acquire exclusive (writer) lock
    if (!lockFile(fd, true)) {
        printSecureError("failed to acquire exclusive write lock on log file");
        ::close(fd);
        return 1;
    }
 
    // Rebuild current gallery state from existing log
    std::unordered_map<std::string, PersonState> state;

    {
        // get each log entry line
        std::ifstream in(logPath);
        if (in.is_open()) {
            std::string line;
            while (std::getline(in, line)) {
                LogEntry e;
                if (!parseLogLine(line, e)) {
                    // Malformed or invalid entry -> skip defensively
                    continue;
                }
                // update state of each person based on action and room (if they are inside gallery and which room)
                auto &ps = state[e.personId];

                if (e.action == "ENTER") {
                    ps.inside = true;
                    ps.room = e.roomId;
                } else if (e.action == "MOVE") {
                    // For existing log, assume it was valid when written
                    ps.inside = true;
                    ps.room = e.roomId;
                } else if (e.action == "EXIT") {
                    ps.inside = false;
                    ps.room.clear();
                }
            }
        }
    }

    // Enforce gallery rules for the NEW event
    auto it = state.find(personId);
    // checks if person exists in log
    bool currentlyKnown = (it != state.end());
    // checks if person is inside the gallery
    bool currentlyInside = currentlyKnown && it->second.inside;
    // current room person is in
    std::string currentRoom = currentlyInside ? it->second.room : "";

    if (event == "ENTER") {
        // Person cannot ENTER if already inside
        if (currentlyInside) {
            std::cerr << "Error: person '" << personId
                      << "' is already inside (in room '" << currentRoom
                      << "'), cannot ENTER again\n";
            unlockFile(fd);
            ::close(fd);
            return 2;
        }
        // For ENTER, roomId should be a real room, not "-"
        if (roomId == "-") {
            std::cerr << "Error: ENTER requires a concrete room, not '-'\n";
            unlockFile(fd);
            ::close(fd);
            return 2;
        }
    } else if (event == "MOVE") {
        // Must already be inside to MOVE
        if (!currentlyInside) {
            std::cerr << "Error: person '" << personId
                      << "' is not currently inside, cannot MOVE\n";
            unlockFile(fd);
            ::close(fd);
            return 2;
        }
        // Cannot MOVE to the same room
        if (roomId == currentRoom) {
            std::cerr << "Error: person '" << personId
                      << "' is already in room '" << roomId
                      << "', cannot MOVE to the same room\n";
            unlockFile(fd);
            ::close(fd);
            return 2;
        }
        // Moving to "-" makes no sense
        if (roomId == "-") {
            std::cerr << "Error: MOVE requires a concrete room, not '-'\n";
            unlockFile(fd);
            ::close(fd);
            return 2;
        }
    } else if (event == "EXIT") {
        // Must be inside to EXIT
        if (!currentlyInside) {
            std::cerr << "Error: person '" << personId
                      << "' is not currently inside, cannot EXIT\n";
            unlockFile(fd);
            ::close(fd);
            return 2;
        }
        // For EXIT, either roomId == "-" or matches the current room
        if (!(roomId == "-" || roomId == currentRoom)) {
            std::cerr << "Error: EXIT room '" << roomId
                      << "' does not match current room '" << currentRoom
                      << "' for person '" << personId << "'\n";
            unlockFile(fd);
            ::close(fd);
            return 2;
        }
    }

    // Build and append the new log entry
    LogEntry newEntry;
    newEntry.timestamp = getCurrentTimestamp();
    newEntry.actorId   = user->actorId;  // authenticated user ID
    newEntry.personId  = personId;
    newEntry.action    = event;
    newEntry.roomId    = roomId;

    std::string logLine = formatLogEntry(newEntry);

    ssize_t written = write(fd, logLine.c_str(), logLine.size());
    if (written != static_cast<ssize_t>(logLine.size())) {
        printSecureError("failed to write log entry");
        unlockFile(fd);
        ::close(fd);
        return 1;
    }

    // Release lock and close
    unlockFile(fd);
    ::close(fd);

    std::cout << "Successfully appended log entry" << std::endl;

    return 0;
}
