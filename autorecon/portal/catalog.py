"""Read the same plugin definitions used by the scanner."""

import argparse
import importlib.util
import inspect
from pathlib import Path

import platformdirs

from autorecon.plugins import AutoRecon, PortScan, Report, ServiceScan


def plugin_catalog():
	"""Return plugin and option metadata without starting a scan."""
	user_dir = Path(platformdirs.user_data_dir('AutoRecon')) / 'plugins'
	bundled_dir = Path(__file__).resolve().parent.parent / 'default-plugins'
	plugin_dir = user_dir if user_dir.is_dir() else bundled_dir
	registry = AutoRecon()
	registry.argparse = argparse.ArgumentParser(add_help=False)
	for path in sorted(plugin_dir.glob('*.py')):
		if path.name.startswith('_'):
			continue
		spec = importlib.util.spec_from_file_location('autorecon.portal.catalog_' + path.stem.replace('-', '_'), str(path))
		module = importlib.util.module_from_spec(spec)
		spec.loader.exec_module(module)
		for _, cls in inspect.getmembers(module, inspect.isclass):
			if cls.__module__ != module.__name__:
				continue
			if issubclass(cls, (PortScan, ServiceScan, Report)):
				registry.register(cls(), path.name)
	plugins = []
	for plugin in registry.plugins.values():
		if isinstance(plugin, PortScan):
			kind = 'port'
		elif isinstance(plugin, ServiceScan):
			kind = 'service'
		else:
			kind = 'report'
		options = []
		prefix = '--' + plugin.slug + '.'
		for action in registry.argparse._actions:
			match = next((name for name in action.option_strings if name.startswith(prefix)), None)
			if not match:
				continue
			if isinstance(action, (argparse._StoreTrueAction, argparse._StoreFalseAction)):
				option_kind = 'boolean'
			elif action.choices:
				option_kind = 'choice'
			elif action.nargs == '+':
				option_kind = 'list'
			else:
				option_kind = 'text'
			options.append({
				'name': match[2:],
				'kind': option_kind,
				'default': action.default,
				'choices': list(action.choices) if action.choices else [],
				'help': action.help or '',
			})
		plugins.append({
			'slug': plugin.slug,
			'name': plugin.name,
			'kind': kind,
			'tags': sorted(set(plugin.tags + [plugin.slug])),
			'description': plugin.description or '',
			'options': options,
		})
	plugins.sort(key=lambda item: (item['kind'], item['name'].lower()))
	return {'plugins': plugins, 'tags': sorted({tag for plugin in plugins for tag in plugin['tags']})}
