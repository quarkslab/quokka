# Examples

## Finding the string difference between two functions
```python
import quokka

# Let's get interested in this patch for the CVE-2018-9555:
# https://android.googlesource.com/platform/system/bt/+/02fc52878d8dba16b860fbdf415b6e4425922b2c%5E%21/#F0

# Load the vuln program using its export
vuln = quokka.Program('vuln.Quokka',
                          'vuln_bluetooth.so')

# Load the fix program using its export
fix = quokka.Program('fix.Quokka',
                         'fix_bluetooth.so')

# Assume we know that the patched function is "l2c_lcc_proc_pdu"
vuln_function = vuln.get_function("l2c_lcc_proc_pdu", approximative=True)
fix_function = fix.get_function("l2c_lcc_proc_pdu", approximative=True)

assert (vuln_function and fix_function)

# Vuln functions strings
vuln_strings = vuln_function.strings
fix_strings = fix_function.strings

diff_strings = [x for x in fix_strings if x not in vuln_strings]
print(diff_strings)

# Output : ['%s: Invalid sdu_length: %d', '112321180']
# Nice ! Indeed, the "112321180" is actually the android bug id that is added during the patch

# Extract from the patch:
#
# +      L2CAP_TRACE_ERROR("%s: Invalid sdu_length: %d", __func__, sdu_length);
# +      android_errorWriteWithInfoLog(0x534e4554, "112321180", -1, NULL, 0);

```