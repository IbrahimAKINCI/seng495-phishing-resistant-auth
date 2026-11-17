# Module C: adversarial test suite and evaluation

Module C attacks the team's own authentication service and measures the three login
methods (password, password + TOTP, passkey). Only the team's own service is tested.

## What has been done

- Statistics code (median, percentile, bootstrap interval) with tests.
- Readers for the friction log and the server timing log, with a format test.
- A recorder that saves attack results, and a script that builds a results table from them.
- A replay attack test for the password and password + TOTP methods.

## Folders

| Folder | Content |
| --- | --- |
| `attacks/` | Attack tests |
| `harness/` | Statistics, log readers, result recorder, results table script |
| `tests_c/` | Tests of the Module C tools |

## How to run

```
pytest attacks tests_c
python -m harness.report
```
