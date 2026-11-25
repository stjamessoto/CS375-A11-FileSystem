# CS375 Lab A11: Simplified Filesystem with Security Features

This project is an in-memory, FFS-like filesystem written in C. It has inodes, direct and
indirect blocks, hard and soft links, owner/group/other permissions, group ACLs, XOR
encryption, and a tamper-evident log. A test program runs 10 tests, and each test is
sized to fit in one screenshot.

## Folder layout

```
CS375-A11-FileSystem/
├── README.md               <- you are here
├── Makefile                <- make | make test | make report | make submission
├── src/                    <- SOURCE CODE (what you submit)
│   ├── simplefs.h          shared structs + function prototypes
│   ├── simplefs.c          filesystem implementation (all 3 coding tasks)
│   ├── fs_test.c           test program: ./fs_test [0-9 | list]
│   └── Makefile
├── report/
│   ├── report.tex          LaTeX report (answers to every question are already written)
│   ├── report.pdf          built by `make report`
│   └── screenshots/        <- PUT YOUR SCREENSHOTS HERE (names listed in its README)
└── submission/             <- WHAT TO SUBMIT (filled by `make submission`)
    └── CS375_A11_Submission.zip
```

## Quick start

```bash
cd /root/CS375-A11-FileSystem
make            # build src/fs_test
make test       # run all 10 tests (should end with: 45 checks passed, 0 failed)
```

To run one test, use `cd src && ./fs_test 5`. To list all tests, use `./fs_test list`.

## Where each lab requirement lives

| Requirement | Code | Test |
|-------------|------|------|
| Inodes, 4 KB blocks, directory | `simplefs.h`, `create_file_ex()`, `read_file()` | 1 |
| Access control (owner/group/other) | `check_permission()` | 2 |
| Hard links + ref count | `create_hard_link()`, `delete_file()` | 3 |
| Soft links (+ dangling, loops) | `create_soft_link()`, `resolve()` | 4 |
| **Coding Task 1:** indirect blocks | `store_data()`, `get_block_ptr()`, `load_data()` | 5 |
| Encryption (XOR, key 0x55) | `store_data()` / `load_data()` | 6 |
| **Coding Task 2:** group ACLs | `create_group()`, `add_acl_entry()`, `check_permission()` | 7 |
| **Coding Task 3:** log verification | `compute_log_hash()`, `verify_logs()`, `print_logs()` | 8 |
| Performance analysis | `test_performance()` in `fs_test.c` | 9 |
| Original lab driver output | `test_original_demo()` | 0 |

## Status: ready to submit

| Step | Status |
|------|--------|
| Source code builds with no warnings; 45/45 checks pass | ✅ |
| 11 screenshots in `report/screenshots/`, each checked against its test | ✅ (see `report/screenshots/README.md`) |
| `report.tex`: name, date, and Test 9 performance numbers filled in | ✅ |
| `report/report.pdf` rebuilt with all screenshots embedded | ✅ |
| `submission/CS375_A11_Submission.zip` built | ✅ |

**Next step:** upload `submission/CS375_A11_Submission.zip`. If your course wants the
files separately, upload the individual files inside `submission/` instead.

## If you change anything

1. **Retake a screenshot:** save it in `report/screenshots/`, not in `submission/`. Use
   the exact file name listed in `report/screenshots/README.md`.
   * On WSL, run `explorer.exe .` from inside `report/screenshots`. This opens the folder
     in Windows, and you can save snips (Win + Shift + S) straight into it.
2. **Retake Test 9:** copy its 8 timing numbers into the `\perf...` macros in the
   `EDIT ME` block at the top of `report/report.tex`. Also update the numbers quoted in
   the "Analysis" paragraph.
3. **Rebuild everything:** run `make submission`. This rebuilds the PDF, copies the source
   and screenshots, and recreates the zip.

## Changes from the handout code (also explained in the report)

* The provided `fs_test.c` could not compile, because its `extern struct` used
  incomplete types. Both files now share `simplefs.h`.
* `struct simplefs` is larger than 8 MB, so it is allocated on the heap with
  `fs_create()`.
* Permission bits are now checked at the correct indices. The handout's code checked
  `permissions[4]` for read access, which is the group-write bit. Because of this fix,
  the demo uses `rw-r-----`, so UID 1002 is still denied as the handout expects.
* Soft links are now resolved by path. Before, they read inode 0 by accident.
* `read_file` no longer writes past the end of the buffer.
* The log hash is now keyed and chained, so tampering can be detected.
