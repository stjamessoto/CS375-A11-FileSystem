# Screenshots

Each screenshot must be saved in **this folder** (`report/screenshots/`) with **exactly** the
file name below. `report.tex` picks them up automatically, and a missing one shows a grey
placeholder box. Do not save screenshots in `submission/screenshots/`, because
`make submission` rebuilds that folder.

All 11 screenshots are present and were checked on 2026-11-25. Each one shows the correct
test, and every check in it reports `[PASS]`.

| # | File name | Command (run in `src/`) | Status |
|---|-----------|-------------------------|--------|
| 1 | `01_build.png`                   | `make clean && make` | ✅ compiles with no warnings |
| 2 | `02_test0_original_demo.png`     | `./fs_test 0` | ✅ read, denied, hard/soft link reads, 7 log entries OK |
| 3 | `03_test1_basic.png`             | `./fs_test 1` | ✅ 5/5 passed |
| 4 | `04_test2_access_control.png`    | `./fs_test 2` | ✅ 7/7 passed |
| 5 | `05_test3_hard_links.png`        | `./fs_test 3` | ✅ 6/6 passed |
| 6 | `06_test4_soft_links.png`        | `./fs_test 4` | ✅ 7/7 passed |
| 7 | `07_test5_indirect_blocks.png`   | `./fs_test 5` | ✅ 5/5 passed |
| 8 | `08_test6_encryption.png`        | `./fs_test 6` | ✅ 2/2 passed |
| 9 | `09_test7_group_acls.png`        | `./fs_test 7` | ✅ 9/9 passed |
| 10 | `10_test8_log_verification.png` | `./fs_test 8` | ✅ 3/3 passed, tampered entries flagged |
| 11 | `11_test9_performance.png`      | `./fs_test 9` | ✅ 1/1 passed; numbers copied into `report.tex` |

The checks total 45 passed and 0 failed.

## Retaking a screenshot

```bash
cd /root/CS375-A11-FileSystem/src && clear && ./fs_test N      # N = 0..9
```

Capture from the `TEST N:` banner down to the prompt. If you retake Test 9, copy its 8
timing numbers into the `\perf...` macros at the top of `report/report.tex`, and update the
numbers quoted in the report's "Analysis" paragraph. Then run `make submission` from the
project root.
