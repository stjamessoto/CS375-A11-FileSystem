# Submission folder

**Don't edit or save files here by hand.** `make submission` deletes this folder's
contents and rebuilds them every time it runs. Put screenshots in `report/screenshots/`.
(As a safety net, any image found here is copied to `report/screenshots/` before the
folder is rebuilt.)

Run this from the project root to rebuild the folder:

```bash
make submission
```

That command fills this folder with:

| Item | What it is |
|------|------------|
| `source/simplefs.c`        | Filesystem implementation (deliverable) |
| `source/simplefs.h`        | Shared header (needed to compile) |
| `source/fs_test.c`         | User-space test program (deliverable) |
| `source/Makefile`          | `make` builds `fs_test` |
| `screenshots/01_…11_*.png` | 11 program-output screenshots (deliverable) |
| `CS375_A11_Report.pdf`     | Report with all screenshots and answers to every question (deliverable) |
| `CS375_A11_Submission.zip` | All of the above in one zip. **Upload this file.** |
