# Test Log Fix for wolfProvider

This branch fixes the issue where test-suite.log is empty during make distcheck failures.

## Changes Made

1. Added a custom test log driver (`test/unit.test.log-driver`) that:
   - Captures all test output to the individual test log file
   - Appends the test output to test-suite.log
   - Properly creates the .trs file for automake

2. Updated `test/include.am` to use the custom test log driver:
   ```
   TEST_LOG_DRIVER = $(top_srcdir)/test/unit.test.log-driver
   ```

## Testing the Fix

To test the fix, run:

```bash
# Clean environment
echo "" > ./test-suite.log

# Run with forced failure to test error logging
source ./scripts/utils-wolfprovider.sh && WOLFPROV_FORCE_FAIL=1 make check

# View the log file
cat ./test-suite.log
```

The test-suite.log should now contain the full test output, including the "###### TESTSUITE SUCCESS" or "###### TESTSUITE FAILED" message.

## Notes

- This fix doesn't address the underlying linking errors with SP math functions
- The fix is focused solely on ensuring test output is properly captured in test-suite.log
