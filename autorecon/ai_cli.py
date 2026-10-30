"""Command line entry point for optional ChatGPT-backed scan reports."""

import argparse
import sys
import webbrowser

import jwt
import requests

from autorecon.ai_auth import ChatGPTAuthError, login, logout, session
from autorecon.ai_report import available_models, create_report


def main(argv=None):
	parser = argparse.ArgumentParser(prog='autorecon-ai', description='Optional post-scan AI reports using your authorized ChatGPT plan.')
	subparsers = parser.add_subparsers(dest='command', required=True)
	subparsers.add_parser('login', help='Authorize AutoRecon to use your ChatGPT plan in a browser.')
	subparsers.add_parser('status', help='Show the locally connected ChatGPT account.')
	subparsers.add_parser('models', help='List models available to the connected account.')
	subparsers.add_parser('logout', help='Revoke and remove the local ChatGPT connection.')
	report_parser = subparsers.add_parser('report', help='Preview or submit a post-scan AI report.')
	report_parser.add_argument('results_dir', help='A target results directory containing scans/.')
	report_parser.add_argument('--file', action='append', default=[], help='Include only this relative scan file. Repeat to include more files.')
	report_parser.add_argument('--model', help='Model slug from autorecon-ai models; required with --send.')
	report_parser.add_argument('--max-chunks', type=int, default=24, help='Maximum scan section requests sent to ChatGPT (default: 24).')
	report_parser.add_argument('--send', action='store_true', help='Send the previewed scan text to OpenAI and save ai-report.md.')
	args = parser.parse_args(argv)
	try:
		if args.command == 'login':
			record = login()
			print('ChatGPT plan connected for {}.'.format(record.get('email') or record['subject']))
		elif args.command == 'status':
			record = session()
			print('Connected: {}'.format(record.get('email') or record['subject']) if record else 'Not signed in.')
		elif args.command == 'models':
			for slug, display_name in available_models():
				print('{}\t{}'.format(slug, display_name))
		elif args.command == 'logout':
			print('Signed out.' if logout() else 'No ChatGPT connection to remove.')
		elif args.command == 'report':
			if args.max_chunks < 1:
				raise ValueError('--max-chunks must be positive.')
			preview, count, report = create_report(args.results_dir, args.model, args.file, args.max_chunks, args.send)
			print('Input preview: {}'.format(preview))
			print('Scan section requests: {}{}'.format(count, ' plus one consolidation request' if args.send else ' if submitted'))
			if report:
				print('AI report: {}'.format(report))
			else:
				print('Nothing was sent. Review the preview, then run this command with --model MODEL --send.')
	except (ChatGPTAuthError, ValueError, OSError, webbrowser.Error, requests.RequestException, jwt.PyJWTError, KeyError) as exc:
		print('AutoRecon AI: {}'.format(exc), file=sys.stderr)
		return 1
	return 0


if __name__ == '__main__':
	sys.exit(main())
