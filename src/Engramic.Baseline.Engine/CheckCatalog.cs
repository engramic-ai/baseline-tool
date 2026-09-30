namespace Engramic.Baseline.Engine;

/// <summary>
/// The checks an audit can run, in the order they run and reports list them. Built explicitly, one
/// check at a time: nothing is found by reflection or loaded from a path.
/// </summary>
public sealed class CheckCatalog
{
    private readonly Check[] _checks;
    private readonly Dictionary<string, Check> _byId;

    private CheckCatalog(Check[] checks)
    {
        _checks = checks;
        _byId = checks.ToDictionary(c => c.Info.Id, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>Gets every check, in order.</summary>
    public IReadOnlyList<Check> Checks => _checks;

    /// <summary>Finds a check by identifier, without regard to case.</summary>
    /// <param name="id">The identifier, such as SU-01.</param>
    /// <returns>The check, or null when there is none with that identifier.</returns>
    public Check? Find(string id)
    {
        ArgumentNullException.ThrowIfNull(id);
        return _byId.GetValueOrDefault(id);
    }

    /// <summary>Lists the checks a selection matches, in catalog order.</summary>
    /// <param name="selection">Which checks to run.</param>
    /// <returns>The checks.</returns>
    public IReadOnlyList<Check> Select(CheckSelection selection)
    {
        ArgumentNullException.ThrowIfNull(selection);
        return [.. _checks.Where(c => selection.Matches(c.Info))];
    }

    /// <summary>
    /// Builds a catalog. Each check is validated as it is added, as the PowerShell tool's Register-CECheck
    /// does: a well-formed identifier that no other check has, a title, a reference and at least one framework.
    /// </summary>
    public sealed class Builder
    {
        private readonly List<Check> _checks = [];
        private readonly HashSet<string> _ids = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Adds a check at the end.</summary>
        /// <param name="check">The check.</param>
        /// <returns>This builder.</returns>
        /// <exception cref="ArgumentException">The check is not valid, or another check has its identifier.</exception>
        public Builder Add(Check check)
        {
            ArgumentNullException.ThrowIfNull(check);
            var info = check.Info ?? throw new ArgumentException($"{check.GetType().Name} has no CheckInfo.", nameof(check));
            Validate(info);
            if (!_ids.Add(info.Id))
            {
                throw new ArgumentException($"Duplicate check id {info.Id}", nameof(check));
            }

            _checks.Add(check);
            return this;
        }

        /// <summary>Adds checks at the end, in order.</summary>
        /// <param name="checks">The checks.</param>
        /// <returns>This builder.</returns>
        /// <exception cref="ArgumentException">A check is not valid, or another check has its identifier.</exception>
        public Builder AddRange(IEnumerable<Check> checks)
        {
            ArgumentNullException.ThrowIfNull(checks);
            foreach (var check in checks)
            {
                Add(check);
            }

            return this;
        }

        /// <summary>Builds the catalog from the checks added so far.</summary>
        /// <returns>The catalog.</returns>
        public CheckCatalog Build() => new([.. _checks]);

        private static void Validate(CheckInfo info)
        {
            if (!CheckIds.IsWellFormed(info.Id))
            {
                throw new ArgumentException($"'{info.Id}' is not a check identifier: two capital letters, a hyphen and two digits, such as SU-01.", nameof(info));
            }

            if (!Enum.IsDefined(info.Category) || !Enum.IsDefined(info.Severity) || !Enum.IsDefined(info.Scope))
            {
                throw new ArgumentException($"{info.Id} has an unknown category, severity or scope.", nameof(info));
            }

            if (string.IsNullOrWhiteSpace(info.Title) || string.IsNullOrWhiteSpace(info.Reference))
            {
                throw new ArgumentException($"{info.Id} needs a title and a reference.", nameof(info));
            }

            if (info.Frameworks is null || info.Frameworks.Count == 0 || info.Frameworks.Any(string.IsNullOrWhiteSpace))
            {
                throw new ArgumentException($"{info.Id} needs at least one framework, and no empty one.", nameof(info));
            }
        }
    }
}
