// simplefs.h
// Public interface for the simplified, in-memory FFS-like filesystem.
// CS375 Lab A11 - Designing and Implementing a Simplified Filesystem
//
// Features:
//   * Inodes with 12 direct block pointers + 1 single-indirect block pointer
//   * 4 KB data blocks with a free-block bitmap (first-fit allocation)
//   * Directory of name -> inode mappings, hard links (ref counted) and soft links
//   * Owner / group / other permission bits ("rwxr-xr-x")
//   * Group-based ACLs (group ID + read/write flags)
//   * XOR "encryption" of all file data at rest
//   * Secure, hash-chained operation log with tamper detection

#ifndef SIMPLEFS_H
#define SIMPLEFS_H

#include <stddef.h>
#include <time.h>

// ---------------------------------------------------------------- limits ----
#define BLOCK_SIZE          4096
#define MAX_BLOCKS          2048          // 8 MB simulated "disk"
#define MAX_INODES          128
#define MAX_DIR_ENTRIES     128
#define MAX_NAME            256
#define MAX_LOGS            100
#define NUM_DIRECT          12            // direct pointers per inode
#define PTRS_PER_BLOCK      ((int)(BLOCK_SIZE / sizeof(int)))   // 1024
#define MAX_FILE_BLOCKS     (NUM_DIRECT + PTRS_PER_BLOCK)       // 1036
#define MAX_FILE_SIZE       ((long)MAX_FILE_BLOCKS * BLOCK_SIZE) // ~4.05 MB
#define MAX_GROUPS          16
#define MAX_GROUP_MEMBERS   16
#define MAX_ACL_ENTRIES     8
#define MAX_INODES_PER_UID  64            // DoS protection: per-user inode quota
#define MAX_SYMLINK_DEPTH   8             // prevents symlink loops
#define XOR_KEY             0x55          // simulated AES key
#define NO_BLOCK            (-1)
#define NO_GROUP            (-1)

// ----------------------------------------------------------- error codes ----
enum fs_error {
    FS_OK             =  0,
    FS_ERR_NOT_FOUND  = -1,
    FS_ERR_PERMISSION = -2,
    FS_ERR_NO_SPACE   = -3,
    FS_ERR_EXISTS     = -4,
    FS_ERR_DANGLING   = -5,
    FS_ERR_INVALID    = -6,
    FS_ERR_QUOTA      = -7,
    FS_ERR_LOOP       = -8
};

// ------------------------------------------------------------ structures ----

// Group-based ACL entry: members of `gid` get the listed rights.
struct acl_entry {
    int gid;
    int can_read;
    int can_write;
};

// Inode structure
struct inode {
    int id;
    int in_use;
    int size;                       // bytes
    char permissions[10];           // e.g. "rw-r-----" (owner|group|other)
    int ref_count;                  // number of hard links
    int blocks[NUM_DIRECT];         // direct block pointers
    int indirect_block;             // block holding PTRS_PER_BLOCK more pointers
    int owner_uid;
    int gid;                        // owning group (NO_GROUP if none)
    struct acl_entry acl[MAX_ACL_ENTRIES];
    int acl_count;
    time_t timestamp;
};

// Directory entry
struct dir_entry {
    char name[MAX_NAME];
    int inode_id;                   // -1 for soft links
    int is_soft_link;               // 1 = soft link, 0 = hard link
    char link_path[MAX_NAME];       // target name for soft links
    int owner_uid;                  // creator of the entry
};

// Log entry (hash chained: each hash covers the previous entry's hash)
struct log_entry {
    char operation[MAX_NAME];
    time_t timestamp;
    int seq;                        // monotonically increasing sequence number
    int inode_id;
    unsigned int prev_hash;
    unsigned int hash;
};

// User group
struct group {
    int gid;
    char name[32];
    int members[MAX_GROUP_MEMBERS];
    int member_count;
};

// Filesystem structure (large: allocate with fs_create(), not on the stack)
struct simplefs {
    char blocks[MAX_BLOCKS][BLOCK_SIZE];   // data blocks
    unsigned char block_used[MAX_BLOCKS];  // free-block bitmap
    struct inode inodes[MAX_INODES];
    struct dir_entry directory[MAX_DIR_ENTRIES];
    struct log_entry logs[MAX_LOGS];       // circular buffer
    struct group groups[MAX_GROUPS];
    int block_count;                       // blocks in use
    int inode_count;                       // inodes in use
    int dir_count;
    int log_count;                         // total logs ever written
    int group_count;
    unsigned int last_log_hash;
    int logging_enabled;
};

// ------------------------------------------------------------- lifecycle ----
struct simplefs *fs_create(void);           // malloc + init_fs
void fs_destroy(struct simplefs *fs);
void init_fs(struct simplefs *fs);

// --------------------------------------------------------- file operations --
int create_file(struct simplefs *fs, const char *name, const char *permissions, int uid,
                const char *data);
int create_file_ex(struct simplefs *fs, const char *name, const char *permissions, int uid,
                   int gid, const char *data, int len);
int read_file(struct simplefs *fs, const char *name, int uid, char *buffer, int max_len);
int read_file_at(struct simplefs *fs, const char *name, int uid, int offset, char *buffer,
                 int len);
int write_file(struct simplefs *fs, const char *name, int uid, const char *data, int len);
int delete_file(struct simplefs *fs, const char *name, int uid);

// ------------------------------------------------------------------ links ---
int create_hard_link(struct simplefs *fs, const char *existing_name, const char *new_name, int uid);
int create_soft_link(struct simplefs *fs, const char *existing_name, const char *new_name, int uid);

// ------------------------------------------------------- groups and ACLs ----
int create_group(struct simplefs *fs, int gid, const char *name);
int add_user_to_group(struct simplefs *fs, int gid, int uid);
int set_file_group(struct simplefs *fs, const char *name, int uid, int gid);
int add_acl_entry(struct simplefs *fs, const char *name, int uid, int gid, int can_read,
                  int can_write);
int check_permission(struct simplefs *fs, const struct inode *inode, int uid, char mode);

// -------------------------------------------------------------- logging -----
unsigned int compute_log_hash(const struct log_entry *entry);
int verify_logs(struct simplefs *fs);       // returns number of bad entries
void print_logs(struct simplefs *fs);

// ------------------------------------------------------- inspection utils ---
void list_directory(struct simplefs *fs);
void print_inode(struct simplefs *fs, const char *name);
int get_physical_block(struct simplefs *fs, const char *name, int logical_index);
int free_block_count(struct simplefs *fs);
const char *fs_strerror(int code);

#endif // SIMPLEFS_H
