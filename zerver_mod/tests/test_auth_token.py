from typing import Dict

from zerver.models import UserProfile
from zerver.tests import test_message_fetch

from ..models import AuthToken


class GetOldMessagesUsingAuthTokenTest(test_message_fetch.GetOldMessagesTest):
    HTTP_AUTHORIZATION: Dict[str, str] = {}

    def login_user(self, user_profile: UserProfile) -> None:
        auth_token, _ = AuthToken.objects.get_or_create(user_profile=user_profile, name="default")
        self.HTTP_AUTHORIZATION["HTTP_AUTHORIZATION"] = f"Token {auth_token.token}"

    def logout(self) -> None:
        del self.HTTP_AUTHORIZATION["HTTP_AUTHORIZATION"]

    def client_get(self, url, *args, **kwargs) -> "TestHttpResponse":
        if url.startswith("/json/"):
            url = "/api/v1" + url[5:]
        return super().client_get(url, *args, **{**kwargs, **self.HTTP_AUTHORIZATION})

    def client_post(self, url, *args, **kwargs) -> "TestHttpResponse":
        if url.startswith("/json/"):
            url = "/api/v1" + url[5:]
        return super().client_post(url, *args, **{**kwargs, **self.HTTP_AUTHORIZATION})

    test_unauthenticated_get_messages = None
    test_unauthenticated_narrow_to_web_public_streams = None
    test_get_messages_with_web_public = None
