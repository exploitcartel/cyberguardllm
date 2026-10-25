"""Resolve saved selections against the installed registry before running Garak."""


def select_installed_probes(selections, inventory):
    catalog = {}
    for name, active in inventory:
        catalog[name.removeprefix('probes.')] = active
    selected, errors = [], []
    for original in selections:
        name = original.strip().removeprefix('garak.').removeprefix('probes.')
        if not name:
            continue
        matches = ([name] if name in catalog else
                   sorted(p for p, active in catalog.items() if active and p.startswith(name + '.')))
        if not matches:
            errors.append(dict(entry_type='configuration_error', probe=original,
                message=f"Garak selection '{original}' has no runnable installed probe. Use an installed module.ClassName; OWASP codes and labels are not Garak probe names. Valid selections continue; this selection was not tested."))
        for probe in matches:
            if probe not in selected:
                selected.append(probe)
    return selected, errors
