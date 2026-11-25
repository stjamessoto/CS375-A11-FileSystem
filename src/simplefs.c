// simplefs.c
// Simplified in-memory FFS-like filesystem with security features.
// CS375 Lab A11
//
// Coding tasks implemented here:
//   Task 1 - Indirect blocks : store_data(), get_block_ptr(), set_block_ptr(),
//                              create_file_ex(), read_file(), read_file_at()
//   Task 2 - Group ACLs      : create_group(), add_user_to_group(), add_acl_entry(),
//                              check_permission() (used by read_file / write_file)
//   Task 3 - Log verification: compute_log_hash(), verify_logs(), print_logs()

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#include "simplefs.h"

// Secret mixed into every log hash. In a real system this would be an HMAC key
// kept outside the filesystem (e.g. in a TPM or kernel keyring).
static const char LOG_SECRET[] = "cs375-simplefs-log-key";

// ======================================================================
//  Small helpers
// ======================================================================

static int min_int(int a, int b) { return a < b ? a : b; }

const char *fs_strerror(int code) {
    switch (code) {
        case FS_OK:             return "OK";
        case FS_ERR_NOT_FOUND:  return "file not found";
        case FS_ERR_PERMISSION: return "permission denied";
        case FS_ERR_NO_SPACE:   return "no space left (or file too large)";
        case FS_ERR_EXISTS:     return "name already exists";
        case FS_ERR_DANGLING:   return "dangling soft link (target missing)";
        case FS_ERR_INVALID:    return "invalid argument";
        case FS_ERR_QUOTA:      return "per-user inode quota exceeded";
        case FS_ERR_LOOP:       return "too many levels of soft links";
        default:                return (code >= 0) ? "OK" : "unknown error";
    }
}

static int find_entry(struct simplefs *fs, const char *name) {
    for (int i = 0; i < fs->dir_count; i++)
        if (strcmp(fs->directory[i].name, name) == 0) return i;
    return -1;
}

static struct group *find_group(struct simplefs *fs, int gid) {
    for (int i = 0; i < fs->group_count; i++)
        if (fs->groups[i].gid == gid) return &fs->groups[i];
    return NULL;
}

static int user_in_group(struct simplefs *fs, int gid, int uid) {
    struct group *g = find_group(fs, gid);
    if (!g) return 0;
    for (int i = 0; i < g->member_count; i++)
        if (g->members[i] == uid) return 1;
    return 0;
}

static int valid_permissions(const char *p) {
    if (!p || strlen(p) != 9) return 0;
    const char *expect = "rwxrwxrwx";
    for (int i = 0; i < 9; i++)
        if (p[i] != '-' && p[i] != expect[i]) return 0;
    return 1;
}

// ======================================================================
//  Secure logging  (Coding Task 3)
// ======================================================================

static unsigned int fnv1a(unsigned int h, const void *data, size_t n) {
    const unsigned char *p = (const unsigned char *)data;
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

// Keyed FNV-1a hash over every field of the entry, including the previous
// entry's hash (hash chain) and a sequence number (detects deletion/reordering).
unsigned int compute_log_hash(const struct log_entry *e) {
    unsigned int h = 2166136261u;
    h = fnv1a(h, LOG_SECRET, strlen(LOG_SECRET));
    h = fnv1a(h, e->operation, strnlen(e->operation, MAX_NAME));
    h = fnv1a(h, &e->timestamp, sizeof e->timestamp);
    h = fnv1a(h, &e->seq, sizeof e->seq);
    h = fnv1a(h, &e->inode_id, sizeof e->inode_id);
    h = fnv1a(h, &e->prev_hash, sizeof e->prev_hash);
    return h;
}

static void add_log(struct simplefs *fs, int inode_id, const char *fmt, ...) {
    if (!fs->logging_enabled) return;
    struct log_entry *log = &fs->logs[fs->log_count % MAX_LOGS];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(log->operation, MAX_NAME, fmt, ap);
    va_end(ap);
    log->timestamp = time(NULL);
    log->seq = fs->log_count;
    log->inode_id = inode_id;
    log->prev_hash = fs->last_log_hash;
    log->hash = compute_log_hash(log);
    fs->last_log_hash = log->hash;
    fs->log_count++;
}

// Status codes for a single log entry
#define LOG_OK          0
#define LOG_TAMPERED    1   // contents no longer match the stored hash
#define LOG_CHAIN_BROKE 2   // entry was removed / reordered / replaced

// Index (in fs->logs) of the k-th oldest entry still in the circular buffer.
static int log_slot(struct simplefs *fs, int k) {
    int stored = min_int(fs->log_count, MAX_LOGS);
    int first = fs->log_count - stored;
    return (first + k) % MAX_LOGS;
}

static int check_log_entry(struct simplefs *fs, int k, const struct log_entry *prev) {
    const struct log_entry *e = &fs->logs[log_slot(fs, k)];
    if (compute_log_hash(e) != e->hash) return LOG_TAMPERED;
    if (prev && (e->prev_hash != prev->hash || e->seq != prev->seq + 1)) return LOG_CHAIN_BROKE;
    return LOG_OK;
}

int verify_logs(struct simplefs *fs) {
    int stored = min_int(fs->log_count, MAX_LOGS);
    int bad = 0;
    const struct log_entry *prev = NULL;
    for (int k = 0; k < stored; k++) {
        if (check_log_entry(fs, k, prev) != LOG_OK) bad++;
        prev = &fs->logs[log_slot(fs, k)];
    }
    return bad;
}

void print_logs(struct simplefs *fs) {
    int stored = min_int(fs->log_count, MAX_LOGS);
    printf("Filesystem Logs (%d total, showing %d):\n", fs->log_count, stored);
    const struct log_entry *prev = NULL;
    int bad = 0;
    for (int k = 0; k < stored; k++) {
        const struct log_entry *e = &fs->logs[log_slot(fs, k)];
        int status = check_log_entry(fs, k, prev);
        char when[16];
        strftime(when, sizeof when, "%H:%M:%S", localtime(&e->timestamp));
        printf("  #%-3d [%ld %s] %-52s (Hash: 0x%08x) %s\n", e->seq, (long)e->timestamp, when,
               e->operation, e->hash,
               status == LOG_OK ? "[OK]"
               : status == LOG_TAMPERED ? "<-- [TAMPERED: hash mismatch]"
                                        : "<-- [TAMPERED: chain broken]");
        if (status != LOG_OK) bad++;
        prev = e;
    }
    if (bad == 0)
        printf("Log integrity check: all %d entries verified OK\n", stored);
    else
        printf("Log integrity check: WARNING - %d of %d entries FAILED verification!\n", bad,
               stored);
}

// ======================================================================
//  Block allocation and indirect blocks  (Coding Task 1)
// ======================================================================

int free_block_count(struct simplefs *fs) { return MAX_BLOCKS - fs->block_count; }

// First-fit allocation keeps a file's blocks close together (FFS-style locality).
static int alloc_block(struct simplefs *fs) {
    for (int b = 0; b < MAX_BLOCKS; b++) {
        if (!fs->block_used[b]) {
            fs->block_used[b] = 1;
            fs->block_count++;
            memset(fs->blocks[b], 0, BLOCK_SIZE);
            return b;
        }
    }
    return NO_BLOCK;
}

static void free_block(struct simplefs *fs, int b) {
    if (b >= 0 && b < MAX_BLOCKS && fs->block_used[b]) {
        fs->block_used[b] = 0;
        fs->block_count--;
        memset(fs->blocks[b], 0, BLOCK_SIZE);  // scrub freed data
    }
}

// Logical block index -> physical block number (direct or via indirect block).
static int get_block_ptr(struct simplefs *fs, const struct inode *inode, int idx) {
    if (idx < 0 || idx >= MAX_FILE_BLOCKS) return NO_BLOCK;
    if (idx < NUM_DIRECT) return inode->blocks[idx];
    if (inode->indirect_block == NO_BLOCK) return NO_BLOCK;
    int ptr;
    memcpy(&ptr, fs->blocks[inode->indirect_block] + (idx - NUM_DIRECT) * sizeof(int), sizeof ptr);
    return ptr;
}

static void set_block_ptr(struct simplefs *fs, struct inode *inode, int idx, int block) {
    if (idx < NUM_DIRECT) {
        inode->blocks[idx] = block;
    } else {
        memcpy(fs->blocks[inode->indirect_block] + (idx - NUM_DIRECT) * sizeof(int), &block,
               sizeof block);
    }
}

static int blocks_needed(int len) {
    int nblocks = (len + BLOCK_SIZE - 1) / BLOCK_SIZE;
    return nblocks + (nblocks > NUM_DIRECT ? 1 : 0);  // +1 for the indirect block
}

static int blocks_held(const struct inode *inode) {
    return blocks_needed(inode->size);
}

static void free_inode_blocks(struct simplefs *fs, struct inode *inode) {
    int nblocks = (inode->size + BLOCK_SIZE - 1) / BLOCK_SIZE;
    for (int i = 0; i < nblocks; i++) free_block(fs, get_block_ptr(fs, inode, i));
    if (inode->indirect_block != NO_BLOCK) free_block(fs, inode->indirect_block);
    for (int i = 0; i < NUM_DIRECT; i++) inode->blocks[i] = NO_BLOCK;
    inode->indirect_block = NO_BLOCK;
    inode->size = 0;
}

// Allocate blocks for `data`, encrypt it (XOR) and record pointers in the inode.
// Caller must have verified there is enough free space.
static int store_data(struct simplefs *fs, struct inode *inode, const char *data, int len) {
    int nblocks = (len + BLOCK_SIZE - 1) / BLOCK_SIZE;
    for (int i = 0; i < NUM_DIRECT; i++) inode->blocks[i] = NO_BLOCK;
    inode->indirect_block = NO_BLOCK;

    if (nblocks > NUM_DIRECT) {
        inode->indirect_block = alloc_block(fs);
        for (int k = 0; k < PTRS_PER_BLOCK; k++) {
            int none = NO_BLOCK;
            memcpy(fs->blocks[inode->indirect_block] + k * sizeof(int), &none, sizeof none);
        }
    }
    for (int i = 0; i < nblocks; i++) {
        int b = alloc_block(fs);
        set_block_ptr(fs, inode, i, b);
        int off = i * BLOCK_SIZE;
        int chunk = min_int(BLOCK_SIZE, len - off);
        for (int j = 0; j < chunk; j++)
            fs->blocks[b][j] = (char)(data[off + j] ^ XOR_KEY);  // simulated encryption
    }
    inode->size = len;
    return FS_OK;
}

// Decrypt `len` bytes starting at byte `offset` of the file into `out`.
static int load_data(struct simplefs *fs, const struct inode *inode, int offset, char *out,
                     int len) {
    if (offset < 0 || offset >= inode->size || len <= 0) return 0;
    len = min_int(len, inode->size - offset);
    int done = 0;
    while (done < len) {
        int pos = offset + done;
        int b = get_block_ptr(fs, inode, pos / BLOCK_SIZE);  // O(1) random access
        int in_block = pos % BLOCK_SIZE;
        int chunk = min_int(BLOCK_SIZE - in_block, len - done);
        for (int j = 0; j < chunk; j++) out[done + j] = (char)(fs->blocks[b][in_block + j] ^ XOR_KEY);
        done += chunk;
    }
    return done;
}

// ======================================================================
//  Access control  (Coding Task 2)
// ======================================================================

// mode is 'r' or 'w'. Order: owner bits -> owning group bits -> group ACLs -> other bits.
int check_permission(struct simplefs *fs, const struct inode *inode, int uid, char mode) {
    int off = (mode == 'r') ? 0 : 1;
    const char *p = inode->permissions;

    if (uid == inode->owner_uid) return p[0 + off] == mode;

    int in_owner_group = 0;
    if (inode->gid != NO_GROUP && user_in_group(fs, inode->gid, uid)) {
        in_owner_group = 1;
        if (p[3 + off] == mode) return 1;
    }
    for (int i = 0; i < inode->acl_count; i++) {
        const struct acl_entry *a = &inode->acl[i];
        if (user_in_group(fs, a->gid, uid) && (mode == 'r' ? a->can_read : a->can_write))
            return 1;
    }
    if (in_owner_group) return 0;  // group class matched: "other" bits do not apply
    return p[6 + off] == mode;
}

int create_group(struct simplefs *fs, int gid, const char *name) {
    if (fs->group_count >= MAX_GROUPS) return FS_ERR_NO_SPACE;
    if (find_group(fs, gid)) return FS_ERR_EXISTS;
    struct group *g = &fs->groups[fs->group_count++];
    memset(g, 0, sizeof *g);
    g->gid = gid;
    snprintf(g->name, sizeof g->name, "%s", name);
    add_log(fs, -1, "Created group %s (GID %d)", name, gid);
    return FS_OK;
}

int add_user_to_group(struct simplefs *fs, int gid, int uid) {
    struct group *g = find_group(fs, gid);
    if (!g) return FS_ERR_NOT_FOUND;
    if (user_in_group(fs, gid, uid)) return FS_OK;
    if (g->member_count >= MAX_GROUP_MEMBERS) return FS_ERR_NO_SPACE;
    g->members[g->member_count++] = uid;
    add_log(fs, -1, "Added UID %d to group %s (GID %d)", uid, g->name, gid);
    return FS_OK;
}

// ======================================================================
//  Name resolution (follows soft links)
// ======================================================================

static int resolve(struct simplefs *fs, const char *name, int depth) {
    int idx = find_entry(fs, name);
    if (idx < 0) return depth > 0 ? FS_ERR_DANGLING : FS_ERR_NOT_FOUND;
    struct dir_entry *e = &fs->directory[idx];
    if (e->is_soft_link) {
        if (depth >= MAX_SYMLINK_DEPTH) return FS_ERR_LOOP;
        return resolve(fs, e->link_path, depth + 1);
    }
    return e->inode_id;
}

// Only the owner may change a file's group or ACL (prevents privilege escalation).
static int owner_inode(struct simplefs *fs, const char *name, int uid, struct inode **out) {
    int id = resolve(fs, name, 0);
    if (id < 0) return id;
    struct inode *inode = &fs->inodes[id];
    if (inode->owner_uid != uid) {
        add_log(fs, id, "DENIED metadata change on %s by UID %d", name, uid);
        return FS_ERR_PERMISSION;
    }
    *out = inode;
    return FS_OK;
}

int set_file_group(struct simplefs *fs, const char *name, int uid, int gid) {
    struct inode *inode;
    int rc = owner_inode(fs, name, uid, &inode);
    if (rc < 0) return rc;
    if (gid != NO_GROUP && !find_group(fs, gid)) return FS_ERR_NOT_FOUND;
    inode->gid = gid;
    add_log(fs, inode->id, "Set group of %s to GID %d by UID %d", name, gid, uid);
    return FS_OK;
}

int add_acl_entry(struct simplefs *fs, const char *name, int uid, int gid, int can_read,
                  int can_write) {
    struct inode *inode;
    int rc = owner_inode(fs, name, uid, &inode);
    if (rc < 0) return rc;
    if (!find_group(fs, gid)) return FS_ERR_NOT_FOUND;
    for (int i = 0; i < inode->acl_count; i++) {  // update existing entry
        if (inode->acl[i].gid == gid) {
            inode->acl[i].can_read = can_read;
            inode->acl[i].can_write = can_write;
            add_log(fs, inode->id, "Updated ACL on %s: GID %d %c%c", name, gid,
                    can_read ? 'r' : '-', can_write ? 'w' : '-');
            return FS_OK;
        }
    }
    if (inode->acl_count >= MAX_ACL_ENTRIES) return FS_ERR_NO_SPACE;
    inode->acl[inode->acl_count++] = (struct acl_entry){gid, can_read, can_write};
    add_log(fs, inode->id, "Added ACL on %s: GID %d %c%c", name, gid, can_read ? 'r' : '-',
            can_write ? 'w' : '-');
    return FS_OK;
}

// ======================================================================
//  Lifecycle
// ======================================================================

void init_fs(struct simplefs *fs) {
    memset(fs, 0, sizeof(struct simplefs));
    for (int i = 0; i < MAX_INODES; i++) {
        fs->inodes[i].id = i;
        fs->inodes[i].indirect_block = NO_BLOCK;
        fs->inodes[i].gid = NO_GROUP;
        for (int j = 0; j < NUM_DIRECT; j++) fs->inodes[i].blocks[j] = NO_BLOCK;
    }
    fs->block_count = 0;
    fs->inode_count = 0;
    fs->dir_count = 0;
    fs->log_count = 0;
    fs->group_count = 0;
    fs->last_log_hash = 0;
    fs->logging_enabled = 1;
}

struct simplefs *fs_create(void) {
    struct simplefs *fs = malloc(sizeof(struct simplefs));
    if (fs) init_fs(fs);
    return fs;
}

void fs_destroy(struct simplefs *fs) { free(fs); }

// ======================================================================
//  File operations
// ======================================================================

int create_file(struct simplefs *fs, const char *name, const char *permissions, int uid,
                const char *data) {
    return create_file_ex(fs, name, permissions, uid, NO_GROUP, data, (int)strlen(data));
}

int create_file_ex(struct simplefs *fs, const char *name, const char *permissions, int uid,
                   int gid, const char *data, int len) {
    if (!name || !*name || strlen(name) >= MAX_NAME || !valid_permissions(permissions) || len < 0)
        return FS_ERR_INVALID;
    if (find_entry(fs, name) >= 0) return FS_ERR_EXISTS;
    if (fs->dir_count >= MAX_DIR_ENTRIES || fs->inode_count >= MAX_INODES) return FS_ERR_NO_SPACE;

    int owned = 0;  // DoS protection: limit inodes per user
    for (int i = 0; i < MAX_INODES; i++)
        if (fs->inodes[i].in_use && fs->inodes[i].owner_uid == uid) owned++;
    if (owned >= MAX_INODES_PER_UID) {
        add_log(fs, -1, "DENIED create %s by UID %d (quota)", name, uid);
        return FS_ERR_QUOTA;
    }

    if ((len + BLOCK_SIZE - 1) / BLOCK_SIZE > MAX_FILE_BLOCKS) return FS_ERR_NO_SPACE;
    if (blocks_needed(len) > free_block_count(fs)) return FS_ERR_NO_SPACE;

    struct inode *inode = NULL;
    for (int i = 0; i < MAX_INODES; i++) {
        if (!fs->inodes[i].in_use) { inode = &fs->inodes[i]; break; }
    }
    memset(inode, 0, sizeof *inode);
    inode->id = (int)(inode - fs->inodes);
    inode->in_use = 1;
    snprintf(inode->permissions, sizeof inode->permissions, "%s", permissions);
    inode->ref_count = 1;
    inode->owner_uid = uid;
    inode->gid = gid;
    inode->timestamp = time(NULL);
    store_data(fs, inode, data, len);
    fs->inode_count++;

    struct dir_entry *entry = &fs->directory[fs->dir_count++];
    memset(entry, 0, sizeof *entry);
    snprintf(entry->name, MAX_NAME, "%s", name);
    entry->inode_id = inode->id;
    entry->is_soft_link = 0;
    entry->owner_uid = uid;

    add_log(fs, inode->id, "Created file %s by UID %d", name, uid);
    return inode->id;
}

int read_file(struct simplefs *fs, const char *name, int uid, char *buffer, int max_len) {
    if (!buffer || max_len <= 0) return FS_ERR_INVALID;
    int id = resolve(fs, name, 0);
    if (id < 0) {
        add_log(fs, -1, "FAILED read %s by UID %d (%s)", name, uid, fs_strerror(id));
        return id;
    }
    struct inode *inode = &fs->inodes[id];
    if (!check_permission(fs, inode, uid, 'r')) {
        add_log(fs, id, "DENIED read %s by UID %d", name, uid);
        return FS_ERR_PERMISSION;
    }
    int n = load_data(fs, inode, 0, buffer, max_len - 1);  // leave room for '\0'
    buffer[n] = '\0';
    add_log(fs, id, "Read file %s by UID %d", name, uid);
    return n;
}

// Random-access read of `len` bytes at `offset` (no '\0' appended).
int read_file_at(struct simplefs *fs, const char *name, int uid, int offset, char *buffer,
                 int len) {
    int id = resolve(fs, name, 0);
    if (id < 0) return id;
    struct inode *inode = &fs->inodes[id];
    if (!check_permission(fs, inode, uid, 'r')) {
        add_log(fs, id, "DENIED read %s by UID %d", name, uid);
        return FS_ERR_PERMISSION;
    }
    int n = load_data(fs, inode, offset, buffer, len);
    add_log(fs, id, "Read %d bytes at offset %d of %s by UID %d", n, offset, name, uid);
    return n;
}

int write_file(struct simplefs *fs, const char *name, int uid, const char *data, int len) {
    if (len < 0) return FS_ERR_INVALID;
    int id = resolve(fs, name, 0);
    if (id < 0) return id;
    struct inode *inode = &fs->inodes[id];
    if (!check_permission(fs, inode, uid, 'w')) {
        add_log(fs, id, "DENIED write %s by UID %d", name, uid);
        return FS_ERR_PERMISSION;
    }
    if ((len + BLOCK_SIZE - 1) / BLOCK_SIZE > MAX_FILE_BLOCKS) return FS_ERR_NO_SPACE;
    if (blocks_needed(len) > free_block_count(fs) + blocks_held(inode)) return FS_ERR_NO_SPACE;
    free_inode_blocks(fs, inode);
    store_data(fs, inode, data, len);
    inode->timestamp = time(NULL);
    add_log(fs, id, "Wrote %d bytes to %s by UID %d", len, name, uid);
    return len;
}

int delete_file(struct simplefs *fs, const char *name, int uid) {
    int idx = find_entry(fs, name);
    if (idx < 0) return FS_ERR_NOT_FOUND;
    struct dir_entry *e = &fs->directory[idx];
    int inode_id = e->inode_id;

    if (e->is_soft_link) {
        if (e->owner_uid != uid) {
            add_log(fs, -1, "DENIED delete %s by UID %d", name, uid);
            return FS_ERR_PERMISSION;
        }
    } else {
        struct inode *inode = &fs->inodes[inode_id];
        if (inode->owner_uid != uid && !check_permission(fs, inode, uid, 'w')) {
            add_log(fs, inode_id, "DENIED delete %s by UID %d", name, uid);
            return FS_ERR_PERMISSION;
        }
        inode->ref_count--;
        if (inode->ref_count == 0) {  // last hard link gone: reclaim inode + blocks
            free_inode_blocks(fs, inode);
            inode->in_use = 0;
            inode->acl_count = 0;
            inode->gid = NO_GROUP;
            fs->inode_count--;
        }
    }
    // remove the directory entry (shift the rest down to keep order)
    memmove(&fs->directory[idx], &fs->directory[idx + 1],
            (size_t)(fs->dir_count - idx - 1) * sizeof(struct dir_entry));
    fs->dir_count--;
    add_log(fs, inode_id, "Deleted %s by UID %d", name, uid);
    return FS_OK;
}

// ======================================================================
//  Links
// ======================================================================

int create_hard_link(struct simplefs *fs, const char *existing_name, const char *new_name,
                     int uid) {
    if (!new_name || !*new_name || strlen(new_name) >= MAX_NAME) return FS_ERR_INVALID;
    int id = resolve(fs, existing_name, 0);
    if (id < 0) return id;
    if (find_entry(fs, new_name) >= 0) return FS_ERR_EXISTS;
    if (fs->dir_count >= MAX_DIR_ENTRIES) return FS_ERR_NO_SPACE;
    struct inode *inode = &fs->inodes[id];
    if (inode->owner_uid != uid && !check_permission(fs, inode, uid, 'w')) {
        add_log(fs, id, "DENIED hard link %s -> %s by UID %d", new_name, existing_name, uid);
        return FS_ERR_PERMISSION;
    }
    inode->ref_count++;
    struct dir_entry *entry = &fs->directory[fs->dir_count++];
    memset(entry, 0, sizeof *entry);
    snprintf(entry->name, MAX_NAME, "%s", new_name);
    entry->inode_id = inode->id;
    entry->is_soft_link = 0;
    entry->owner_uid = uid;
    add_log(fs, id, "Created hard link %s to %s by UID %d", new_name, existing_name, uid);
    return FS_OK;
}

int create_soft_link(struct simplefs *fs, const char *existing_name, const char *new_name,
                     int uid) {
    if (!new_name || !*new_name || strlen(new_name) >= MAX_NAME || !existing_name ||
        strlen(existing_name) >= MAX_NAME)
        return FS_ERR_INVALID;
    if (find_entry(fs, new_name) >= 0) return FS_ERR_EXISTS;
    if (fs->dir_count >= MAX_DIR_ENTRIES) return FS_ERR_NO_SPACE;
    struct dir_entry *entry = &fs->directory[fs->dir_count++];
    memset(entry, 0, sizeof *entry);
    snprintf(entry->name, MAX_NAME, "%s", new_name);
    snprintf(entry->link_path, MAX_NAME, "%s", existing_name);
    entry->inode_id = -1;  // soft links have no inode of their own here
    entry->is_soft_link = 1;
    entry->owner_uid = uid;
    add_log(fs, -1, "Created soft link %s to %s by UID %d", new_name, existing_name, uid);
    return FS_OK;
}

// ======================================================================
//  Inspection utilities
// ======================================================================

int get_physical_block(struct simplefs *fs, const char *name, int logical_index) {
    int id = resolve(fs, name, 0);
    if (id < 0) return id;
    return get_block_ptr(fs, &fs->inodes[id], logical_index);
}

void list_directory(struct simplefs *fs) {
    printf("  %-5s  %-9s  %5s  %5s  %5s  %8s  %s\n", "INODE", "PERMS", "LINKS", "OWNER", "GROUP",
           "SIZE", "NAME");
    for (int i = 0; i < fs->dir_count; i++) {
        struct dir_entry *e = &fs->directory[i];
        if (e->is_soft_link) {
            int target = resolve(fs, e->name, 0);
            printf("  %-5s  %-9s  %5s  %5d  %5s  %8s  %s -> %s%s\n", "-", "(symlink)", "-", e->owner_uid, "-", "-", e->name, e->link_path,
                   target < 0 ? "  (DANGLING)" : "");
        } else {
            struct inode *n = &fs->inodes[e->inode_id];
            char grp[16];
            if (n->gid == NO_GROUP) snprintf(grp, sizeof grp, "-");
            else snprintf(grp, sizeof grp, "%d", n->gid);
            printf("  %-5d  %-9s  %5d  %5d  %5s  %8d  %s\n", n->id, n->permissions, n->ref_count,
                   n->owner_uid, grp, n->size, e->name);
        }
    }
    printf("  [%d inodes used, %d/%d blocks used]\n", fs->inode_count, fs->block_count, MAX_BLOCKS);
}

void print_inode(struct simplefs *fs, const char *name) {
    int id = resolve(fs, name, 0);
    if (id < 0) {
        printf("  inode for %s: %s\n", name, fs_strerror(id));
        return;
    }
    struct inode *n = &fs->inodes[id];
    int nblocks = (n->size + BLOCK_SIZE - 1) / BLOCK_SIZE;
    printf("  +--------------------- inode %d (%s) ---------------------\n", n->id, name);
    printf("  | size        : %d bytes (%d data block%s)\n", n->size, nblocks,
           nblocks == 1 ? "" : "s");
    printf("  | permissions : %s   owner UID: %d   group GID: ", n->permissions, n->owner_uid);
    if (n->gid == NO_GROUP) printf("-\n"); else printf("%d\n", n->gid);
    printf("  | ref_count   : %d\n", n->ref_count);
    printf("  | direct[0-11]: ");
    for (int i = 0; i < NUM_DIRECT; i++) {
        if (n->blocks[i] == NO_BLOCK) printf("  -");
        else printf(" %d", n->blocks[i]);
    }
    printf("\n");
    if (n->indirect_block == NO_BLOCK) {
        printf("  | indirect    : (none)\n");
    } else {
        int extra = nblocks - NUM_DIRECT;
        printf("  | indirect    : block %d -> %d pointer%s [", n->indirect_block, extra,
               extra == 1 ? "" : "s");
        for (int i = 0; i < extra && i < 10; i++)
            printf("%s%d", i ? " " : "", get_block_ptr(fs, n, NUM_DIRECT + i));
        printf("%s]\n", extra > 10 ? " ..." : "");
    }
    if (n->acl_count > 0) {
        printf("  | ACL         :");
        for (int i = 0; i < n->acl_count; i++)
            printf(" [GID %d: %c%c]", n->acl[i].gid, n->acl[i].can_read ? 'r' : '-',
                   n->acl[i].can_write ? 'w' : '-');
        printf("\n");
    }
    printf("  +-------------------------------------------------------------\n");
}
