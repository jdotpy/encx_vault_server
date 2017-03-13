from django.core.management.base import BaseCommand, CommandError
from crypt_web.models import User

class Command(BaseCommand):
    help = 'Creates a new crypt administrator'

    def handle(self, *args, **options):
        user_name = input('Enter username:')
        user, token = User.objects.new(user_name, is_admin=True)
        print('New Token:', token)
        print('Run command: "cli.py init" and have the above token ready')
