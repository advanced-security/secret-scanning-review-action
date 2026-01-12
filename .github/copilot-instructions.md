# Copilot Instructions for Secret Scanning Review Action

## Code Quality Standards

### PowerShell Development
When modifying `action.ps1`:
- **ALWAYS** add `.PARAMETER` documentation blocks for any new parameters added to the param() block
- Follow the existing documentation format with description and default value
- Include examples in `.EXAMPLE` blocks when adding significant new functionality
- Add `.NOTES` entries for important implementation details

### Python Development
When modifying `action.py`:
- Add docstrings for new functions following the existing style
- Update module-level comments when adding new functionality
- Keep parameter documentation consistent between Python and PowerShell versions

### Action Configuration
When modifying `action.yml`:
- Add descriptions for all new inputs
- Set appropriate default values
- Mark deprecated inputs with `[DEPRECATED - Use <new-input> instead]` in the description
- Ensure both PowerShell and Python runtime steps receive new parameters when applicable

### Documentation
When adding new features or inputs:
- **ALWAYS** update `README.md` with:
  - New input parameter documentation in the Configuration Options section
  - Add deprecation notices for old parameters
  - Update FAQ section if runtime differences change
  - Update example usage if needed
- Keep feature parity documentation accurate between runtimes
- Use consistent formatting for parameter names (backticks for inline code)

### Feature Parity
- When adding features to one runtime (Python or PowerShell), consider if it should be added to both
- If a feature is runtime-specific (like proxy settings), document it clearly in the FAQ
- Deprecated parameters should maintain backward compatibility

### Testing
- Test new parameters with both `true` and `false` values
- Verify environment variable fallbacks work correctly
- Check YAML syntax for action.yml changes
- Verify step outputs are properly configured in action.yml

## Common Patterns

### Adding a New Input Parameter
1. Add to `action.yml` inputs section with description and default
2. For PowerShell: Add to param() block in `action.ps1` with type
3. For PowerShell: Add `.PARAMETER` documentation in comment-based help
4. For Python: Add to argparse in `action.py` with help text
5. Update both runtime invocations in `action.yml` to pass the parameter
6. Update `README.md` Configuration Options section
7. If replacing an old parameter, mark old one as deprecated but keep for compatibility

### Deprecating an Input
1. Keep the old input in `action.yml` for backward compatibility
2. Update description to `[DEPRECATED - Use <new-input> instead]`
3. In action step commands, use fallback logic: `${{ inputs.new-input || inputs.old-input }}`
4. Document deprecation in `README.md`
5. Do NOT remove the deprecated input without a major version bump

## File-Specific Guidelines

### action.ps1
- Use comment-based help at the top of the file
- Use Write-ActionInfo, Write-ActionDebug, Write-ActionWarning for logging
- Follow existing error handling patterns with try/catch
- Clear sensitive variables after use (e.g., `$GitHubToken = $null`)

### action.py
- Use logging module for output
- Follow existing error handling with proper exit codes
- Keep function names consistent with PowerShell equivalents when possible

### action.yml
- Maintain alphabetical or logical grouping of inputs
- Use double-dollar for PowerShell boolean conversion: `$${{ inputs.param }}`
- Use single-dollar for Python: `${{ inputs.param }}`

## Review Checklist
Before submitting changes:
- [ ] All new parameters documented in code comments
- [ ] README.md updated with new parameters
- [ ] Backward compatibility maintained for deprecated inputs
- [ ] Both runtimes updated if feature applies to both
- [ ] YAML syntax validated
- [ ] Example usage updated if needed
