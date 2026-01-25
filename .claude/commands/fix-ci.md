# Fix CI Errors

Run `just ci-all` and fix all errors that occur.

## Steps

1. First run `just ci-all` to identify errors
2. Fix errors by category:
   - **Format errors**: Run `just fmt` to auto-fix
   - **Clippy errors**: Review warnings and fix code
     - `collapsible_if` → Use let-chain syntax
     - `clone_on_copy` → Remove `.clone()`
     - `manual_strip` → Use `strip_prefix`
     - `useless_format` → Use `.to_string()` instead
     - `field_reassign_with_default` → Set values in struct initializer
     - `assertions_on_constants` → Use meaningful assertions
   - **Test failures**: Fix failing tests
   - **Compile errors**: Fix missing fields or type errors
3. After fixes, run `just ci-all` again to verify all checks pass
4. Report completion when all checks pass

## Notes

- Keep changes minimal
- Do not break existing functionality
- Always verify all tests pass
