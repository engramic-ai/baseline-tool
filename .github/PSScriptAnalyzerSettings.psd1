@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # Console output is the intended UX for the entry-point scripts.
        'PSAvoidUsingWriteHost',
        # Check/remediation helpers use plural nouns deliberately (e.g. Get-CELocalUsers).
        'PSUseSingularNouns',
        # Internal helpers return rich objects; ShouldProcess is implemented where state changes.
        'PSUseShouldProcessForStateChangingFunctions',
        # Check and remediation scriptblocks share a fixed ($ctx) / ($p, $undo) signature.
        'PSReviewUnusedParameter',
        # Tests share mock state through globals on purpose.
        'PSAvoidGlobalVars'
    )
}
