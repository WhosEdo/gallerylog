------------------------------------------------------------
SECURE GALLERY LOG – PROJECT OVERVIEW
------------------------------------------------------------

This project implements a secure, append-only logging system
for an art gallery. Two programs are provided:

  - logappend : Authenticated writer, appends validated events
  - logread   : Authenticated reader, displays the log contents

All access is controlled by tokens with hashed credentials
and role-based permissions.

The log file is:
    logs/gallery.log

It is append-only and created with permissions 0600 (owner
read/write only).

------------------------------------------------------------
FILES
------------------------------------------------------------

src/security_utils.h / src/security_utils.cpp
  - Shared security layer:
      * SHA-256 hashing via OpenSSL to store tokens
      * Built-in token store with roles:
          - AppendOnly  
          - ReadOnly  
          - ReadWrite 
      * Permission checks for Operation::Read / Operation::Append
      * Input validation:
          - validateAction (ENTER / MOVE / EXIT)
          - validateRoomId (whitelisted gallery rooms)
          - validatePersonId (format + length limiting)
      * Log formatting/parsing:
          - timestamp|actorId|personId|action|roomId
      * File open helpers (read-only and append-only)
      * Proper file locking (flock) for readers/writers

src/logread.cpp
  - ./logread -T <token>
  - Authenticates the token for READ operation
  - Opens logs/gallery.log read-only
  - Acquires a shared (reader) file lock (multiple readers allowed)
  - Parses each log line via parseLogLine and prints valid entries

src/logappend.cpp
  - ./logappend -T <token> -E <event> -P <personId> -R <roomId>
    where events are one of: ENTER, MOVE, EXIT
    rooms are one of: lobby, gallery1, gallery2, vault, security, storage, - (for EXIT)

  - Authenticates the token for APPEND operation
  - Opens logs/gallery.log in append-only mode (creates if needed, 0600)
  - Acquires an exclusive (writer) file lock
  - Reconstructs current state for each person by parsing existing log:
      * Tracks whether each person is inside and which room they are in
  - Enforces gallery rules for the new event:
      * ENTER:
          - allowed only if person is not currently inside
          - roomId must be a real room (not "-")
      * MOVE:
          - allowed only if person is currently inside
          - new room must be different from current room
          - roomId must be a real room (not "-")
      * EXIT:
          - allowed only if person is currently inside
          - roomId must be "-" OR match their current room
  - If the new event violates any rule, the program prints an error
    and does NOT append anything.
  - If valid, the program formats and appends the new LogEntry.

src/test_cases.cpp
  - test cases to test proper input validation and token authentication.
  - Compiles to ./test_cases.
  - Runs a series of logappend/logread commands, printing:
      * Description
      * Command
      * Exit code
  - Used to demonstrate security test cases.

logs/
  - Directory for gallery.log (log file is created at runtime).

------------------------------------------------------------
BUILDING (INSIDE WSL)
------------------------------------------------------------

Requirements:
  - WSL with Ubuntu
  - g++ and build-essential
  - OpenSSL development libraries (libssl-dev)

Compile:

  g++ -std=c++17 src/logread.cpp src/security_utils.cpp -o logread -lcrypto
  g++ -std=c++17 src/logappend.cpp src/security_utils.cpp -o logappend -lcrypto
  g++ -std=c++17 src/test_cases.cpp -o test_cases

------------------------------------------------------------
RUNNING
------------------------------------------------------------

Example valid sequence:

  # Clean any existing log:
  rm -f logs/gallery.log

  # Append events:
  ./logappend -T alex-write-123 -E ENTER -P emp001 -R lobby
  ./logappend -T alex-write-123 -E MOVE  -P emp001 -R gallery1
  ./logappend -T alex-write-123 -E EXIT  -P emp001 -R -

  # Read the log:
  ./logread -T kim-read-456

Token roles (example):
  - alex-write-123  -> AppendOnly (can use logappend, not logread)
  - kim-read-456    -> ReadOnly   (can use logread, not logappend)
  - lee-admin-789   -> ReadWrite  (can use both)

------------------------------------------------------------
TEST CASES
------------------------------------------------------------

Automated test runner:

  ./test_cases

This will:
  - Reset logs/gallery.log between groups of tests
  - Run valid sequences
  - Run invalid sequences such as:
      * ENTER twice
      * MOVE before ENTER
      * MOVE to the same room
      * EXIT without ENTER
      * EXIT from the wrong room
      * Using incorrect tokens for read/append
  - Print each command and its exit code for inspection.

You can also see the commands inside src/test_cases.cpp for manual
execution.

------------------------------------------------------------
SECURE CODING PRACTICES USED
------------------------------------------------------------

  - Strong hashing:
      * Tokens are hashed with SHA-256 using OpenSSL. Only hashes are
        stored; plaintext tokens are never embedded in code.

  - Input validation:
      * All user-controlled fields (event, roomId, personId) are
        validated using dedicated functions before processing.
      * Invalid actions or rooms are rejected immediately.

  - Log format validation:
      * Existing log lines are parsed using parseLogLine, which
        re-validates every field before using it for state.

  - State-based checks:
      * logappend enforces semantic rules based on the reconstructed
        history of the log, not just the current input, preventing
        inconsistent states (double ENTER, EXIT without ENTER, etc.).

  - File integrity and locking:
      * logread uses shared locks (LOCK_SH) for concurrent readers.
      * logappend uses exclusive locks (LOCK_EX) for writers.
      * This prevents race conditions and partial writes from corrupting
        the append-only log.

  - Principle of least privilege:
      * Tokens are given the minimum operations they need:
          - ReadOnly vs AppendOnly vs ReadWrite.
      * A token for append cannot use logread and vice versa.

------------------------------------------------------------
END OF README
------------------------------------------------------------
