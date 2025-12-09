# SOFTSEC Supplementary Assignment Summary

## GitHub repository

- Public repo URL: <https://github.com/illusionOvO/tatou.git>

## How to run tests and generate the coverage report

From the project root: tatou 
not tatou/tatou

```bash
TEST_MODE=1 pytest --cov=server/src --cov-branch --cov-report=html:htmlcov 
```

# GitHub Actions pull request
- PR URL (dev -> main): [162cb807fa9624be6aa77c285d536b35c6529f8b](https://github.com/illusionOvO/tatou/pull/2)
The ci.yml GitHub Actions workflow runs pytest with TEST_MODE=1 on every pull request targeting the main branch.

## List of new tests (supplementary folder)
server/unitest/supplementary/test_create_watermark_success.py
    Happy-path creation of a watermark with mocked watermarking methods.

server/unitest/supplementary/test_create_watermark_bad_request.py
    Missing or invalid fields (document id, method, intended_for, secret, key) return 400.

server/unitest/supplementary/test_create_watermark_503.py
    Simulated database insert errors return 503.

server/unitest/supplementary/test_create_watermark_remaining_branches.py
    - document id coming from query/body and invalid ids (400).
    - Invalid document path (500).
    - Document not found (404).
    - Watermarking method not applicable (400).
    - Applicability check raising an exception (400).
    - Empty watermark output (500).
    - Watermarking failure (500).
    - Errors when writing the watermarked file (500).

server/unitest/supplementary/test_read_watermark_success.py
    Successful read-watermark call with mocked read_watermark.

server/unitest/supplementary/test_read_watermark_400s.py
    Missing or invalid document id, missing method/key return 400.

server/unitest/supplementary/test_read_watermark_fail.py
    - File path outside STORAGE_DIR returns 500.
    - File missing on disk returns 410.
    - Database errors return 503.
    - Internal watermark reading errors return 400.


## Uncovered branches and justification
In create_watermark, the IntegrityError branch that checks
    "Duplicate entry" in msg and "uq_Versions_link" in msg is not covered.
        - This branch depends on a specific UNIQUE constraint and exact error
        - message from the production database backend.
        - Reproducing the same integrity error message reliably in the in-memory
        - test database is fragile and would tightly couple the tests to the
        - database engine’s error string.
For this reason, the branch is treated as defensive code and is documented but not exercised in unit tests.