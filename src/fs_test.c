// fs_test.c
// User-space test driver for simplefs.
// CS375 Lab A11
//
// Usage:
//   ./fs_test          run every test, one after another
//   ./fs_test N        run only test N (0-9), handy for screenshots
//   ./fs_test list     show the list of tests
//
// Every test starts from a fresh, empty filesystem so its output is self-contained.

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "simplefs.h"

#define BUFFER_SIZE 4096

static int passed = 0, failed = 0;

// ------------------------------------------------------------- helpers -----

static void banner(int n, const char *title) {
    printf("\n");
    printf("==================================================================\n");
    printf("  TEST %d: %s\n", n, title);
    printf("==================================================================\n");
}

static void section(const char *title) { printf("\n--- %s ---\n", title); }

static void check(int cond, const char *what) {
    printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what);
    if (cond) passed++; else failed++;
}

static void show_result(const char *who, int rc, const char *buffer) {
    if (rc >= 0) printf("  %s -> OK (%d bytes): \"%s\"\n", who, rc, buffer);
    else printf("  %s -> ERROR %d: %s\n", who, rc, fs_strerror(rc));
}

static void hexdump(const char *label, const char *data, int n) {
    printf("  %-11s hex  : ", label);
    for (int i = 0; i < n; i++) printf("%02x ", (unsigned char)data[i]);
    printf("\n  %-11s ascii: ", label);
    for (int i = 0; i < n; i++) {
        unsigned char c = (unsigned char)data[i];
        printf("%c", (c >= 32 && c < 127) ? c : '.');
    }
    printf("\n");
}

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

// ------------------------------------------------------------- tests -------

// TEST 0: the original lab driver (file ops, links, logs) in one run.
static void test_original_demo(void) {
    banner(0, "Original lab demo (create, read, links, logs)");
    struct simplefs *fs = fs_create();
    char buffer[BUFFER_SIZE];

    // NOTE: the lab handout used "rw-r--r--" but then expected UID 1002 to be
    // denied. With correct owner/group/other checking, "other" must not have 'r'
    // for that to be denied, so we use "rw-r-----".
    create_file(fs, "file1.txt", "rw-r-----", 1001, "Hello, Filesystem!");

    if (read_file(fs, "file1.txt", 1001, buffer, BUFFER_SIZE) > 0)
        printf("Read: %s\n", buffer);
    else
        printf("Read failed\n");

    if (read_file(fs, "file1.txt", 1002, buffer, BUFFER_SIZE) < 0)
        printf("Permission denied for UID 1002\n");

    create_hard_link(fs, "file1.txt", "file1_link.txt", 1001);
    if (read_file(fs, "file1_link.txt", 1001, buffer, BUFFER_SIZE) > 0)
        printf("Hard link read: %s\n", buffer);

    create_soft_link(fs, "file1.txt", "file1_soft.txt", 1001);
    if (read_file(fs, "file1_soft.txt", 1001, buffer, BUFFER_SIZE) > 0)
        printf("Soft link read: %s\n", buffer);

    printf("\nDirectory listing:\n");
    list_directory(fs);
    printf("\n");
    print_logs(fs);
    fs_destroy(fs);
}

// TEST 1: basic file creation and reading
static void test_basic(void) {
    banner(1, "File creation and reading (inodes)");
    struct simplefs *fs = fs_create();
    char buffer[BUFFER_SIZE];

    int id = create_file(fs, "file1.txt", "rw-r-----", 1001, "Hello, Filesystem!");
    printf("  create_file(\"file1.txt\") returned inode %d\n", id);
    check(id >= 0, "file1.txt created");

    int id2 = create_file(fs, "notes.txt", "rw-r--r--", 1001, "CS375 lab notes");
    check(id2 >= 0, "notes.txt created");

    int rc = create_file(fs, "file1.txt", "rw-------", 1001, "duplicate");
    printf("  create duplicate file1.txt -> %s\n", fs_strerror(rc));
    check(rc == FS_ERR_EXISTS, "duplicate names are rejected");

    rc = read_file(fs, "file1.txt", 1001, buffer, BUFFER_SIZE);
    show_result("read file1.txt (UID 1001)", rc, buffer);
    check(rc == 18 && strcmp(buffer, "Hello, Filesystem!") == 0, "contents read back correctly");

    rc = read_file(fs, "missing.txt", 1001, buffer, BUFFER_SIZE);
    show_result("read missing.txt", rc, buffer);
    check(rc == FS_ERR_NOT_FOUND, "missing file reports not found");

    section("Directory listing");
    list_directory(fs);
    section("Inode of file1.txt");
    print_inode(fs, "file1.txt");
    fs_destroy(fs);
}

// TEST 2: owner/group/other access control
static void test_access_control(void) {
    banner(2, "Access control (owner / group / other permission bits)");
    struct simplefs *fs = fs_create();
    char buffer[BUFFER_SIZE];

    create_file(fs, "private.txt", "rw-------", 1001, "owner only");
    create_file(fs, "public.txt", "rw-r--r--", 1001, "anyone may read");
    list_directory(fs);
    printf("\n");

    int rc = read_file(fs, "private.txt", 1001, buffer, BUFFER_SIZE);
    show_result("UID 1001 (owner) reads private.txt", rc, buffer);
    check(rc > 0, "owner can read own file");

    rc = read_file(fs, "private.txt", 1002, buffer, BUFFER_SIZE);
    show_result("UID 1002 (other) reads private.txt", rc, buffer);
    check(rc == FS_ERR_PERMISSION, "Permission denied for UID 1002");

    rc = read_file(fs, "public.txt", 1002, buffer, BUFFER_SIZE);
    show_result("UID 1002 (other) reads public.txt ", rc, buffer);
    check(rc > 0, "other can read a world-readable file");

    rc = write_file(fs, "public.txt", 1002, "hacked!", 7);
    printf("  UID 1002 writes public.txt -> %s\n", fs_strerror(rc));
    check(rc == FS_ERR_PERMISSION, "other cannot write (no 'w' in other bits)");

    rc = delete_file(fs, "private.txt", 1002);
    printf("  UID 1002 deletes private.txt -> %s\n", fs_strerror(rc));
    check(rc == FS_ERR_PERMISSION, "other cannot delete someone else's file");

    rc = add_acl_entry(fs, "private.txt", 1002, 0, 1, 1);
    printf("  UID 1002 tries to grant itself access (ACL change) -> %s\n", fs_strerror(rc));
    check(rc == FS_ERR_PERMISSION, "non-owner cannot change ACL (no privilege escalation)");

    rc = write_file(fs, "private.txt", 1001, "owner updated", 13);
    read_file(fs, "private.txt", 1001, buffer, BUFFER_SIZE);
    show_result("UID 1001 writes then reads private.txt", rc, buffer);
    check(rc == 13 && strcmp(buffer, "owner updated") == 0, "owner can write own file");

    section("Security log (denied attempts are recorded)");
    print_logs(fs);
    fs_destroy(fs);
}

// TEST 3: hard links
static void test_hard_links(void) {
    banner(3, "Hard links (shared inode + reference count)");
    struct simplefs *fs = fs_create();
    char buffer[BUFFER_SIZE];

    create_file(fs, "file1.txt", "rw-r-----", 1001, "Hello, Filesystem!");
    int rc = create_hard_link(fs, "file1.txt", "file1_link.txt", 1001);
    check(rc == FS_OK, "hard link file1_link.txt -> file1.txt created");

    rc = read_file(fs, "file1_link.txt", 1001, buffer, BUFFER_SIZE);
    show_result("read file1_link.txt", rc, buffer);
    check(rc > 0, "Hard link read works");

    section("Both names share ONE inode, ref_count = 2");
    list_directory(fs);
    check(fs->inodes[0].ref_count == 2, "ref_count is 2");

    rc = create_hard_link(fs, "file1.txt", "evil_link.txt", 1002);
    printf("\n  UID 1002 tries to hard link file1.txt -> %s\n", fs_strerror(rc));
    check(rc == FS_ERR_PERMISSION, "unauthorized user cannot create hard link");

    section("Delete the ORIGINAL name file1.txt");
    delete_file(fs, "file1.txt", 1001);
    list_directory(fs);
    rc = read_file(fs, "file1_link.txt", 1001, buffer, BUFFER_SIZE);
    show_result("read file1_link.txt after deleting file1.txt", rc, buffer);
    check(rc > 0 && fs->inodes[0].ref_count == 1, "data survives; ref_count dropped to 1");

    section("Delete the last link file1_link.txt");
    int before = fs->block_count;
    delete_file(fs, "file1_link.txt", 1001);
    list_directory(fs);
    check(fs->inode_count == 0 && fs->block_count < before,
          "ref_count hit 0 -> inode and data blocks freed");
    fs_destroy(fs);
}

// TEST 4: soft links
static void test_soft_links(void) {
    banner(4, "Soft (symbolic) links and dangling links");
    struct simplefs *fs = fs_create();
    char buffer[BUFFER_SIZE];

    create_file(fs, "file1.txt", "rw-r-----", 1001, "Hello, Filesystem!");
    int rc = create_soft_link(fs, "file1.txt", "file1_soft.txt", 1001);
    check(rc == FS_OK, "soft link file1_soft.txt -> file1.txt created");

    rc = read_file(fs, "file1_soft.txt", 1001, buffer, BUFFER_SIZE);
    show_result("read file1_soft.txt", rc, buffer);
    check(rc > 0, "Soft link read follows the path to file1.txt");

    section("Soft link does NOT increase the reference count");
    list_directory(fs);
    check(fs->inodes[0].ref_count == 1, "ref_count of file1.txt is still 1");

    rc = read_file(fs, "file1_soft.txt", 1002, buffer, BUFFER_SIZE);
    printf("\n  UID 1002 reads through soft link -> %s\n", fs_strerror(rc));
    check(rc == FS_ERR_PERMISSION, "target's permissions are still enforced via soft link");

    section("Delete the target file1.txt -> soft link becomes dangling");
    delete_file(fs, "file1.txt", 1001);
    list_directory(fs);
    rc = read_file(fs, "file1_soft.txt", 1001, buffer, BUFFER_SIZE);
    show_result("read file1_soft.txt", rc, buffer);
    check(rc == FS_ERR_DANGLING, "soft link fails after target is deleted");

    section("Re-create file1.txt -> soft link works again (it stores a path)");
    create_file(fs, "file1.txt", "rw-r-----", 1001, "A brand new file1");
    rc = read_file(fs, "file1_soft.txt", 1001, buffer, BUFFER_SIZE);
    show_result("read file1_soft.txt", rc, buffer);
    check(rc > 0, "soft link resolves to the NEW file with the same name");

    section("Soft link loop protection");
    create_soft_link(fs, "loopB", "loopA", 1001);
    create_soft_link(fs, "loopA", "loopB", 1001);
    rc = read_file(fs, "loopA", 1001, buffer, BUFFER_SIZE);
    printf("  read loopA (loopA -> loopB -> loopA ...) -> %s\n", fs_strerror(rc));
    check(rc == FS_ERR_LOOP, "symlink loop detected instead of infinite recursion");
    fs_destroy(fs);
}

// TEST 5: indirect blocks (Coding Task 1)
static void test_indirect_blocks(void) {
    banner(5, "Indirect block pointers for large files (Coding Task 1)");
    struct simplefs *fs = fs_create();

    int len = 20 * BLOCK_SIZE + 100;  // 21 blocks: 12 direct + 9 via indirect block
    char *data = malloc(len), *out = malloc(len + 1);
    for (int i = 0; i < len; i++) data[i] = (char)('A' + (i % 26));

    printf("  Creating big.dat with %d bytes (%d blocks; only %d direct pointers)\n", len,
           (len + BLOCK_SIZE - 1) / BLOCK_SIZE, NUM_DIRECT);
    int id = create_file_ex(fs, "big.dat", "rw-r--r--", 1001, NO_GROUP, data, len);
    check(id >= 0, "large file created");
    print_inode(fs, "big.dat");
    printf("  blocks used: %d (21 data + 1 indirect)\n", fs->block_count);
    check(fs->block_count == 22, "21 data blocks + 1 indirect pointer block allocated");

    int rc = read_file(fs, "big.dat", 1001, out, len + 1);
    printf("  read_file returned %d bytes\n", rc);
    check(rc == len && memcmp(data, out, len) == 0, "whole file read back byte-for-byte");

    section("Random access into the indirect region (block 15)");
    char piece[27] = {0};
    int offset = 15 * BLOCK_SIZE + 10;
    rc = read_file_at(fs, "big.dat", 1001, offset, piece, 26);
    printf("  read_file_at(offset=%d, len=26) -> \"%s\"\n", offset, piece);
    printf("  logical block 15 -> physical block %d (found via indirect block)\n",
           get_physical_block(fs, "big.dat", 15));
    check(rc == 26 && memcmp(piece, data + offset, 26) == 0, "random read from indirect block");

    section("Maximum file size");
    printf("  max file size = (%d direct + %d indirect) x %d B = %ld bytes (~%.2f MB)\n",
           NUM_DIRECT, PTRS_PER_BLOCK, BLOCK_SIZE, MAX_FILE_SIZE, MAX_FILE_SIZE / 1048576.0);
    long too_big = MAX_FILE_SIZE + 1;
    char *huge = calloc((size_t)too_big, 1);
    rc = create_file_ex(fs, "huge.dat", "rw-------", 1001, NO_GROUP, huge, (int)too_big);
    printf("  create %ld-byte file -> %s\n", too_big, fs_strerror(rc));
    check(rc == FS_ERR_NO_SPACE, "file larger than max size is rejected");

    free(huge);
    free(data);
    free(out);
    fs_destroy(fs);
}

// TEST 6: encryption at rest
static void test_encryption(void) {
    banner(6, "Data encryption at rest (XOR cipher, key 0x55)");
    struct simplefs *fs = fs_create();
    char buffer[BUFFER_SIZE];
    const char *secret = "Top secret: launch code 1234";

    create_file(fs, "secret.txt", "rw-------", 1001, secret);
    int b = get_physical_block(fs, "secret.txt", 0);
    int n = (int)strlen(secret);
    printf("  secret.txt is stored in physical block %d\n\n", b);
    hexdump("plaintext", secret, n);
    hexdump("on disk", fs->blocks[b], n);

    check(memcmp(fs->blocks[b], secret, n) != 0, "raw block does NOT contain the plaintext");

    int rc = read_file(fs, "secret.txt", 1001, buffer, BUFFER_SIZE);
    printf("\n");
    show_result("read_file (decrypts)", rc, buffer);
    check(rc == n && strcmp(buffer, secret) == 0, "authorized read returns decrypted data");
    fs_destroy(fs);
}

// TEST 7: group-based ACLs (Coding Task 2)
static void test_group_acls(void) {
    banner(7, "Group-based ACLs (Coding Task 2)");
    struct simplefs *fs = fs_create();
    char buffer[BUFFER_SIZE];
    int rc;

    create_group(fs, 500, "developers");
    add_user_to_group(fs, 500, 1002);
    add_user_to_group(fs, 500, 1003);
    create_group(fs, 600, "auditors");
    add_user_to_group(fs, 600, 1005);
    printf("  Groups: developers (GID 500) = {1002, 1003}, auditors (GID 600) = {1005}\n");
    printf("  Users:  1001 = owner, 1004 = outsider\n\n");

    create_file_ex(fs, "project.c", "rw-r-----", 1001, 500, "int main(){return 0;}", 21);
    list_directory(fs);

    section("Owning-group permission bits (r for group 500)");
    rc = read_file(fs, "project.c", 1002, buffer, BUFFER_SIZE);
    show_result("UID 1002 (developers) read ", rc, buffer);
    check(rc > 0, "group member can read (group bits r--)");
    rc = read_file(fs, "project.c", 1004, buffer, BUFFER_SIZE);
    show_result("UID 1004 (outsider)   read ", rc, buffer);
    check(rc == FS_ERR_PERMISSION, "non-member is denied");
    rc = read_file(fs, "project.c", 1005, buffer, BUFFER_SIZE);
    show_result("UID 1005 (auditors)   read ", rc, buffer);
    check(rc == FS_ERR_PERMISSION, "auditors denied before ACL is added");
    rc = write_file(fs, "project.c", 1002, "x", 1);
    printf("  UID 1002 (developers) write -> %s\n", fs_strerror(rc));
    check(rc == FS_ERR_PERMISSION, "group has no write bit");

    section("Owner adds ACLs: auditors r-, developers rw");
    add_acl_entry(fs, "project.c", 1001, 600, 1, 0);
    add_acl_entry(fs, "project.c", 1001, 500, 1, 1);
    print_inode(fs, "project.c");

    rc = read_file(fs, "project.c", 1005, buffer, BUFFER_SIZE);
    show_result("UID 1005 (auditors)   read ", rc, buffer);
    check(rc > 0, "ACL grants auditors read");
    rc = write_file(fs, "project.c", 1005, "x", 1);
    printf("  UID 1005 (auditors)   write -> %s\n", fs_strerror(rc));
    check(rc == FS_ERR_PERMISSION, "ACL does not grant auditors write (least privilege)");
    rc = write_file(fs, "project.c", 1003, "int main(){return 1;}", 21);
    printf("  UID 1003 (developers) write -> %s\n", rc >= 0 ? "OK" : fs_strerror(rc));
    check(rc == 21, "ACL grants developers write");
    rc = read_file(fs, "project.c", 1004, buffer, BUFFER_SIZE);
    show_result("UID 1004 (outsider)   read ", rc, buffer);
    check(rc == FS_ERR_PERMISSION, "outsider still denied");

    section("Privilege escalation attempt");
    rc = add_acl_entry(fs, "project.c", 1004, 600, 1, 1);
    printf("  UID 1004 adds ACL on project.c -> %s\n", fs_strerror(rc));
    check(rc == FS_ERR_PERMISSION, "only the owner may modify ACLs");
    fs_destroy(fs);
}

// TEST 8: secure logging + verification (Coding Task 3)
static void test_logs(void) {
    banner(8, "Secure logging and log verification (Coding Task 3)");
    struct simplefs *fs = fs_create();
    char buffer[BUFFER_SIZE];

    create_file(fs, "payroll.txt", "rw-------", 1001, "salary data");
    read_file(fs, "payroll.txt", 1001, buffer, BUFFER_SIZE);
    read_file(fs, "payroll.txt", 1002, buffer, BUFFER_SIZE);  // denied -> logged
    create_hard_link(fs, "payroll.txt", "payroll_link.txt", 1001);
    create_soft_link(fs, "payroll.txt", "payroll_soft.txt", 1001);
    delete_file(fs, "payroll_link.txt", 1001);

    section("Untouched log");
    print_logs(fs);
    check(verify_logs(fs) == 0, "verify_logs() finds 0 bad entries");

    section("ATTACKER edits the log to hide UID 1002's denied access");
    int slot = 2;  // the "DENIED read" entry
    printf("  before: \"%s\"\n", fs->logs[slot].operation);
    snprintf(fs->logs[slot].operation, MAX_NAME, "Read file payroll.txt by UID 1001");
    printf("  after : \"%s\"\n", fs->logs[slot].operation);

    section("ATTACKER also back-dates entry #4 by one hour");
    fs->logs[4].timestamp -= 3600;

    section("Log after tampering");
    print_logs(fs);
    int bad = verify_logs(fs);
    printf("  verify_logs() returned %d\n", bad);
    check(bad == 2, "both tampered entries are flagged");

    section("ATTACKER edits an entry AND recomputes its hash (without the secret key)");
    init_fs(fs);
    create_file(fs, "a.txt", "rw-------", 1001, "a");
    read_file(fs, "a.txt", 1002, buffer, BUFFER_SIZE);
    read_file(fs, "a.txt", 1001, buffer, BUFFER_SIZE);
    snprintf(fs->logs[1].operation, MAX_NAME, "Read file a.txt by UID 1001");
    // naive unkeyed hash (attacker doesn't know the secret)
    unsigned int h = 5381;
    for (const char *p = fs->logs[1].operation; *p; p++) h = h * 33 + (unsigned char)*p;
    fs->logs[1].hash = h;
    print_logs(fs);
    check(verify_logs(fs) >= 1, "forged hash detected (keyed hash + chain)");
    fs_destroy(fs);
}

// TEST 9: performance - sequential vs random, FFS vs FAT
#define PERF_BLOCKS 1024

// Read + decrypt one FAT cluster (same per-byte cost as simplefs's load_data()).
static void fat_read_block(const char *disk, int cluster, char *out) {
    const char *src = disk + (long)cluster * BLOCK_SIZE;
    for (int j = 0; j < BLOCK_SIZE; j++) out[j] = (char)(src[j] ^ XOR_KEY);
}
#define PERF_PASSES 20

static void test_performance(void) {
    banner(9, "Performance: sequential vs random access (FFS vs FAT)");
    struct simplefs *fs = fs_create();
    fs->logging_enabled = 0;  // don't let logging dominate the timing

    int len = PERF_BLOCKS * BLOCK_SIZE;
    char *data = malloc(len);
    for (int i = 0; i < len; i++) data[i] = (char)(i * 31);
    create_file_ex(fs, "perf.dat", "rw-------", 1001, NO_GROUP, data, len);

    int order[PERF_BLOCKS];
    for (int i = 0; i < PERF_BLOCKS; i++) order[i] = i;
    srand(42);
    for (int i = PERF_BLOCKS - 1; i > 0; i--) {  // Fisher-Yates shuffle
        int j = rand() % (i + 1), t = order[i];
        order[i] = order[j];
        order[j] = t;
    }
    char buf[BLOCK_SIZE];
    volatile int sink = 0;
    long reads = (long)PERF_BLOCKS * PERF_PASSES;

    // --- FFS (inode pointers) ---
    double t0 = now_ms();
    for (int p = 0; p < PERF_PASSES; p++)
        for (int i = 0; i < PERF_BLOCKS; i++) {
            read_file_at(fs, "perf.dat", 1001, i * BLOCK_SIZE, buf, BLOCK_SIZE);
            sink += buf[0];
        }
    double ffs_seq = now_ms() - t0;

    t0 = now_ms();
    for (int p = 0; p < PERF_PASSES; p++)
        for (int i = 0; i < PERF_BLOCKS; i++) {
            read_file_at(fs, "perf.dat", 1001, order[i] * BLOCK_SIZE, buf, BLOCK_SIZE);
            sink += buf[0];
        }
    double ffs_rand = now_ms() - t0;

    // pointer lookups: blocks 0-11 = 1 lookup, blocks >= 12 = 2 (indirect + data)
    long ffs_lookups = (long)PERF_PASSES * (NUM_DIRECT * 1 + (PERF_BLOCKS - NUM_DIRECT) * 2);

    // --- FAT simulation: linked list of blocks in a File Allocation Table ---
    int *fat_next = malloc(sizeof(int) * PERF_BLOCKS);
    int *fat_phys = malloc(sizeof(int) * PERF_BLOCKS);  // logical i -> FAT cluster
    for (int i = 0; i < PERF_BLOCKS; i++) fat_phys[i] = order[i];  // scattered clusters
    for (int i = 0; i < PERF_BLOCKS; i++)
        fat_next[fat_phys[i]] = (i + 1 < PERF_BLOCKS) ? fat_phys[i + 1] : -1;
    char *fat_disk = malloc(len);
    for (int i = 0; i < PERF_BLOCKS; i++)
        for (int j = 0; j < BLOCK_SIZE; j++)  // stored encrypted, same as simplefs
            fat_disk[(long)fat_phys[i] * BLOCK_SIZE + j] = (char)(data[(long)i * BLOCK_SIZE + j] ^ XOR_KEY);
    int fat_start = fat_phys[0];

    long fat_seq_hops = 0, fat_rand_hops = 0;
    t0 = now_ms();
    for (int p = 0; p < PERF_PASSES; p++) {
        int c = fat_start;
        for (int i = 0; i < PERF_BLOCKS; i++) {
            fat_read_block(fat_disk, c, buf);
            sink += buf[0];
            c = fat_next[c];
            fat_seq_hops++;
        }
    }
    double fat_seq = now_ms() - t0;

    t0 = now_ms();
    for (int p = 0; p < PERF_PASSES; p++)
        for (int i = 0; i < PERF_BLOCKS; i++) {
            int c = fat_start;
            for (int k = 0; k < order[i]; k++) {  // walk the chain from the start
                c = fat_next[c];
                fat_rand_hops++;
            }
            fat_rand_hops++;
            fat_read_block(fat_disk, c, buf);
            sink += buf[0];
        }
    double fat_rand = now_ms() - t0;
    (void)sink;

    printf("  File: %d blocks x %d B = %d KB, %d passes => %ld block reads per row\n\n",
           PERF_BLOCKS, BLOCK_SIZE, len / 1024, PERF_PASSES, reads);
    printf("  %-20s %-11s %10s %14s %13s %16s\n", "Layout", "Access", "Total(ms)", "Avg/block(ns)",
           "MB/s", "Pointer lookups");
    printf("  %-20s %-11s %10.2f %14.1f %13.1f %16ld\n", "FFS (inode ptrs)", "Sequential",
           ffs_seq, ffs_seq * 1e6 / reads, (reads * (double)BLOCK_SIZE / 1048576.0) / (ffs_seq / 1000),
           ffs_lookups);
    printf("  %-20s %-11s %10.2f %14.1f %13.1f %16ld\n", "FFS (inode ptrs)", "Random",
           ffs_rand, ffs_rand * 1e6 / reads,
           (reads * (double)BLOCK_SIZE / 1048576.0) / (ffs_rand / 1000), ffs_lookups);
    printf("  %-20s %-11s %10.2f %14.1f %13.1f %16ld\n", "FAT (linked list)", "Sequential",
           fat_seq, fat_seq * 1e6 / reads,
           (reads * (double)BLOCK_SIZE / 1048576.0) / (fat_seq / 1000), fat_seq_hops);
    printf("  %-20s %-11s %10.2f %14.1f %13.1f %16ld\n", "FAT (linked list)", "Random",
           fat_rand, fat_rand * 1e6 / reads,
           (reads * (double)BLOCK_SIZE / 1048576.0) / (fat_rand / 1000), fat_rand_hops);

    printf("\n  Observations:\n");
    printf("   * FFS random ~= FFS sequential: any block is found in <= 2 pointer lookups.\n");
    printf("   * Sequentially, FFS and FAT are about equal (each read is 1-2 pointer\n");
    printf("     lookups); FFS also pays a name lookup + permission check per read.\n");
    printf("   * FAT random is %.1fx slower than FAT sequential: reaching block k walks k links\n",
           fat_rand / (fat_seq > 0 ? fat_seq : 1e-9));
    printf("     (avg %.0f hops per random read vs 1 hop sequentially).\n",
           (double)fat_rand_hops / reads);
    printf("   * In RAM there is no seek time; on an HDD FFS block groups would also keep\n");
    printf("     these blocks physically close, making sequential reads even cheaper.\n");

    check(ffs_lookups < fat_rand_hops,
          "FFS random access needs far fewer pointer lookups than FAT random access");

    free(fat_next);
    free(fat_phys);
    free(fat_disk);
    free(data);
    fs_destroy(fs);
}

// ------------------------------------------------------------- main --------

typedef void (*test_fn)(void);
static const struct { test_fn fn; const char *name; } TESTS[] = {
    {test_original_demo,   "Original lab demo (create, read, links, logs)"},
    {test_basic,           "File creation and reading (inodes)"},
    {test_access_control,  "Access control (owner/group/other)"},
    {test_hard_links,      "Hard links"},
    {test_soft_links,      "Soft links"},
    {test_indirect_blocks, "Indirect blocks (Coding Task 1)"},
    {test_encryption,      "Encryption at rest"},
    {test_group_acls,      "Group-based ACLs (Coding Task 2)"},
    {test_logs,            "Log verification (Coding Task 3)"},
    {test_performance,     "Performance: sequential vs random"},
};
#define NUM_TESTS ((int)(sizeof TESTS / sizeof TESTS[0]))

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "list") == 0) {
        printf("Available tests:\n");
        for (int i = 0; i < NUM_TESTS; i++) printf("  ./fs_test %d   %s\n", i, TESTS[i].name);
        return 0;
    }
    if (argc > 1) {
        char *end;
        long n = strtol(argv[1], &end, 10);
        if (*end || n < 0 || n >= NUM_TESTS) {
            fprintf(stderr, "Usage: %s [0-%d | list]\n", argv[0], NUM_TESTS - 1);
            return 1;
        }
        TESTS[n].fn();
    } else {
        for (int i = 0; i < NUM_TESTS; i++) TESTS[i].fn();
    }
    if (passed + failed > 0)
        printf("\nSummary: %d checks passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
