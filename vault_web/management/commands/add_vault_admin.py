from django.core.management.base import BaseCommand, CommandError
from vault_web.models import User

class Command(BaseCommand):
    help = 'Creates the vault administrator'

    def handle(self, *args, **options):
        username = None
        while username is None:
            response = input('Enter username: ')
            try:
                existing = User.objects.get(user_name=username)
            except User.DoesNotExist:
                username = response
            else:
                print('Username is taken. Try again')

        user, token = User.objects.new(user_name=username, is_admin=True)
        print('New Token:', token)
        print('Run command: "cli.py init" and have the above token ready')
