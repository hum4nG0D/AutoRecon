"""Render report Markdown locally with raw HTML and remote images disabled."""

import html
from urllib.parse import urlsplit

try:
	from markdown_it import MarkdownIt
except ImportError:  # An editable checkout may be used before dependencies are installed.
	MarkdownIt = None


def _safe_link(value):
	url = urlsplit(value)
	return url.scheme.lower() in ('http', 'https', 'mailto') and not url.netloc.startswith('@')


def render_markdown(source):
	if MarkdownIt is None:
		return '<pre>' + html.escape(source) + '</pre>'
	markdown = MarkdownIt('commonmark', {'html': False, 'linkify': False}).enable('table')
	markdown.renderer.rules['image'] = lambda tokens, index, options, env: html.escape(tokens[index].content)
	tokens = markdown.parse(source)
	for token in tokens:
		if token.type != 'inline' or not token.children:
			continue
		for child in token.children:
			if child.type == 'link_open':
				href = child.attrGet('href') or ''
				if _safe_link(href):
					child.attrSet('rel', 'noopener noreferrer')
					child.attrSet('target', '_blank')
				else:
					child.attrSet('href', '#')
					child.attrSet('title', 'Local file links are unavailable in the portal')
	return markdown.renderer.render(tokens, markdown.options, {})


def render_text(source):
	return '<pre>' + html.escape(source) + '</pre>'
