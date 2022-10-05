from rest_framework.test import APITestCase
from authentication.models import User


class TestModels(APITestCase):

    def test_creates_user(self):
        user = User.objects.create_user(
            'testuser', 'testemail', 'testpassword')
        self.assertIsInstance(user, User)
        self.assertFalse(user.is_staff)
        self.assertEqual(user.username, 'testuser')
        self.assertEqual(user.email, 'testemail')

    def test_creates_super_user(self):
        user = User.objects.create_superuser(
            'testuser', 'testemail', 'testpassword')
        self.assertIsInstance(user, User)
        self.assertTrue(user.is_staff)
        self.assertEqual(user.username, 'testuser')
        self.assertEqual(user.email, 'testemail')

    def test_raises_error_when_no_username(self):
        self.assertRaises(ValueError, User.objects.create_user,
                          '', 'testemail', 'testpassword')

    def test_raises_error_when_no_email(self):
        self.assertRaises(ValueError, User.objects.create_user,
                          'testuser', '', 'testpassword')

    def test_raises_error_when_superuser_is_not_staff(self):
        self.assertRaises(ValueError, User.objects.create_superuser,
                          'testuser', 'testemail', 'testpassword', is_staff=False)

    def test_raises_error_when_superuser_is_not_superuser(self):
        self.assertRaises(ValueError, User.objects.create_superuser,
                          'testuser', 'testemail', 'testpassword', is_superuser=False)
