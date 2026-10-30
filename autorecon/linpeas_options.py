"""Map the short LinPEAS options onto the SSH plugin's existing options."""


def apply_linpeas_options(args):
	if not args.linpeas:
		if args.ssh_user or args.ssh_identity:
			raise ValueError('-u/--ssh-user and -i/--ssh-identity require --linpeas.')
		return
	username = 'ssh_authenticated_host_checks.username'
	identity = 'ssh_authenticated_host_checks.identity_file'
	linpeas = 'ssh_authenticated_host_checks.linpeas'
	values = vars(args)
	if args.ssh_user:
		values[username] = args.ssh_user
	if args.ssh_identity:
		values[identity] = args.ssh_identity
	if not values.get(username) or not values.get(identity):
		raise ValueError('--linpeas requires an SSH username and identity file (-u USER -i KEY).')
	values[linpeas] = True
