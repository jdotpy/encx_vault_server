from django.core.management.base import BaseCommand, CommandError
from crypt_web.models import User

class Command(BaseCommand):
    help = 'Creates the crypt administrator'

    def handle(self, *args, **options):
        try:
            existing = User.objects.get(user_name=User.ROOT_USER_NAME)
        except User.DoesNotExist:
            existing = None
        if existing is not None:
            response = input('There is already a root user! Type "delete" to delete this user and start fresh: ') 
            if response == 'delete':
                print('As you wish...') 
                existing.delete()
            else:
                print('Phew! Sanity remains')
                return False

        user, token = User.objects.new(user_name=User.ROOT_USER_NAME, is_admin=True)
        print('New Token:', token)
        print('Run command: "cli.py init" and have the above token ready')
