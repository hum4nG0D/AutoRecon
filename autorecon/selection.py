"""Resolve tag presets and exact plugin selection for scanner and portal."""

import inspect


def parse_include_plugins(value, available_slugs):
	"""Return an exact allowlist, or None for the legacy tag selection mode."""
	if value is None:
		return None
	chosen = {slug.strip().lower() for slug in value.split(',')}
	if not chosen or '' in chosen:
		raise ValueError('--include-plugins requires comma-separated plugin slugs.')
	unknown = chosen - set(available_slugs)
	if unknown:
		raise ValueError('Unknown plugin slug(s) in --include-plugins: {}.'.format(', '.join(sorted(unknown))))
	return chosen


def plugin_selected(plugin, include_plugins, forced_slugs, tag_groups, excluded_tag_groups):
	"""An explicit allowlist overrides tags; legacy force flags retain their behavior."""
	if include_plugins is not None:
		return plugin.slug in include_plugins
	if forced_slugs and plugin.slug in forced_slugs:
		return True
	plugin_tags = set(plugin.tags)
	return (any(set(group).issubset(plugin_tags) for group in tag_groups)
		and not any(set(group).issubset(plugin_tags) for group in excluded_tag_groups))


def failed_plugin_checks(plugins, include_plugins):
	"""Preflight only plugins that can run under the current selection."""
	failures = []
	for slug, plugin in plugins.items():
		if include_plugins is not None and slug not in include_plugins:
			continue
		for member_name, _ in inspect.getmembers(plugin, predicate=inspect.ismethod):
			if member_name == 'check' and plugin.check() is False:
				failures.append(slug)
	return failures


def service_plugin_candidates(plugins, include_plugins):
	"""Include manual-only callbacks only for explicitly selected plugins."""
	for plugin in plugins:
		if include_plugins is None or plugin.slug in include_plugins:
			yield plugin
