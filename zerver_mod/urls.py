from django.urls import include, path, re_path

import zerver.lib.rest

from .views.integration import (
    create_user_backend, deactivate_user_backend, delete_auth_token_backend,
    delete_fcm_token_backend, get_auth_tokens_backend,
    get_or_create_auth_token_backend, get_user_backend,
    partial_update_user_backend, refresh_or_create_auth_token_backend,
    rest_path, update_fcm_token_backend, update_user_backend)
from .views.messages_overview import get_messages_overview_backend

v1_api_and_json_patterns = [
    # GET returns every last message in each stream user subscribed to,
    # and every last message in each private chat.
    # The "unread" field has also been added, which means the number of unread messages
    # in the stream/private chat.
    zerver.lib.rest.rest_path("messages/overview", GET=get_messages_overview_backend),
]

iparty_internal_patterns = [
    rest_path(
        "user/<int:user_id>",
        GET=get_user_backend,
        POST=create_user_backend,
        PUT=update_user_backend,
        PATCH=partial_update_user_backend,
        DELETE=deactivate_user_backend
    ),
    rest_path("user/<int:user_id>/tokens", GET=get_auth_tokens_backend),
    rest_path(
        "user/<int:user_id>/tokens/<str:name>",
        GET=get_or_create_auth_token_backend,
        PUT=refresh_or_create_auth_token_backend,
        DELETE=delete_auth_token_backend
    ),
    rest_path(
        "user/<int:user_id>/tokens/<str:name>/fcm-token",
        PUT=update_fcm_token_backend,
        DELETE=delete_fcm_token_backend
    ),
]

urlpatterns = [
    path("api/v1/", include(v1_api_and_json_patterns)),
    path("json/", include(v1_api_and_json_patterns)),
    path("iparty-internal/v1/", include(iparty_internal_patterns))
]

i18n_urlpatterns = []
