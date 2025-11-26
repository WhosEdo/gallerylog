// test cases to test input validation and token authentication

#include <iostream>
#include <cstdlib>
#include <string>

int runCommand(const std::string& desc, const std::string& cmd) {
    std::cout << "--------------------------------------------------\n";
    std::cout << desc << "\n";
    std::cout << "Command: " << cmd << "\n";
    int rc = std::system(cmd.c_str());
    std::cout << "Exit code: " << rc << "\n";
    return rc;
}

int main() {
    std::cout << "SECURE GALLERY LOG – TEST CASE RUNNER\n";

    // Clean log and ensure logs/ exists
    std::system("mkdir -p logs");
    std::system("rm -f logs/gallery.log");

    // 1) Valid sequence: ENTER -> MOVE -> EXIT
    runCommand(
        "Test 1.1: Valid ENTER",
        "./logappend -T alex-write-123 -E ENTER -P emp001 -R lobby"
    );
    runCommand(
        "Test 1.2: Valid MOVE to gallery1",
        "./logappend -T alex-write-123 -E MOVE -P emp001 -R gallery1"
    );
    runCommand(
        "Test 1.3: Valid EXIT with '-'",
        "./logappend -T alex-write-123 -E EXIT -P emp001 -R -"
    );
    runCommand(
        "Test 1.4: logread after valid sequence",
        "./logread -T kim-read-456"
    );

    // Reset log for negative tests
    std::system("rm -f logs/gallery.log");

    // 2) ENTER twice
    runCommand(
        "Test 2.1: ENTER emp001 into lobby",
        "./logappend -T alex-write-123 -E ENTER -P emp001 -R lobby"
    );
    runCommand(
        "Test 2.2: Second ENTER for same person (should FAIL)",
        "./logappend -T alex-write-123 -E ENTER -P emp001 -R gallery1"
    );

    // 3) MOVE before ENTER
    std::system("rm -f logs/gallery.log");
    runCommand(
        "Test 3.1: MOVE without prior ENTER (should FAIL)",
        "./logappend -T alex-write-123 -E MOVE -P emp002 -R lobby"
    );

    // 4) MOVE to same room
    std::system("rm -f logs/gallery.log");
    runCommand(
        "Test 4.1: ENTER emp003 into lobby",
        "./logappend -T alex-write-123 -E ENTER -P emp003 -R lobby"
    );
    runCommand(
        "Test 4.2: MOVE emp003 to same room lobby (should FAIL)",
        "./logappend -T alex-write-123 -E MOVE -P emp003 -R lobby"
    );

    // 5) EXIT without ENTER
    std::system("rm -f logs/gallery.log");
    runCommand(
        "Test 5.1: EXIT without ENTER (should FAIL)",
        "./logappend -T alex-write-123 -E EXIT -P emp004 -R -"
    );

    // 6) EXIT wrong room
    std::system("rm -f logs/gallery.log");
    runCommand(
        "Test 6.1: ENTER emp005 into lobby",
        "./logappend -T alex-write-123 -E ENTER -P emp005 -R lobby"
    );
    runCommand(
        "Test 6.2: EXIT from wrong room gallery1 (should FAIL)",
        "./logappend -T alex-write-123 -E EXIT -P emp005 -R gallery1"
    );

    // 7) Permission tests
    std::system("rm -f logs/gallery.log");
    runCommand(
        "Test 7.1: Append with READ-ONLY token (should FAIL)",
        "./logappend -T kim-read-456 -E ENTER -P emp006 -R lobby"
    );
    runCommand(
        "Test 7.2: Read with APPEND-ONLY token (should FAIL)",
        "./logread -T alex-write-123"
    );
    runCommand(
        "Test 7.3: Read with READWRITE admin (should SUCCEED or empty)",
        "./logread -T lee-admin-789"
    );

    std::cout << "--------------------------------------------------\n";
    std::cout << "Test run complete. Review outputs and exit codes above.\n";
    return 0;
}
