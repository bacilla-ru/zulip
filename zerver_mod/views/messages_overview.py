from typing import Dict, List

from django.http import HttpRequest, HttpResponse
from sqlalchemy.sql import (
    and_,
    cast,
    column,
    func,
    join,
    literal,
    literal_column,
    not_,
    or_,
    outerjoin,
    select,
    table,
    text,
)
from sqlalchemy.sql.selectable import CTE, SelectBase
from sqlalchemy.types import Boolean, Integer

from zerver.context_processors import get_valid_realm_from_request
from zerver.lib.message import messages_for_ids
from zerver.lib.request import REQ, has_request_variables
from zerver.lib.response import json_success
from zerver.lib.sqlalchemy_utils import get_sqlalchemy_connection
from zerver.lib.utils import statsd
from zerver.lib.validator import check_bool
from zerver.models import UserMessage, UserProfile


@has_request_variables
def get_messages_overview_backend(
    request: HttpRequest,
    user_profile: UserProfile,
    apply_markdown: bool = REQ(json_validator=check_bool, default=True),
) -> HttpResponse:

    realm = get_valid_realm_from_request(request)

    assert realm is not None

    last_messages_cte: CTE = (
        select(
            column("message_id", Integer),
            column("flags", Integer),
            column("recipient_id", Integer),
            column("user_profile_id", Integer)
        )
        .distinct(column("recipient_id", Integer))
        .where(column("user_profile_id", Integer) == literal(user_profile.id))
        .select_from(
            join(
                table("zerver_usermessage"),
                table("zerver_message"),
                column("message_id", Integer) == literal_column("zerver_message.id", Integer),
            )
        )
        .order_by(
            column("recipient_id", Integer),
            column("message_id", Integer).desc()
        )
    ).cte("m")

    unread_cte: CTE = (
        select(
            column("recipient_id", Integer),
            cast(func.count(column("message_id", Integer)), Integer).label("unread")
        )
        .where(
            column("user_profile_id", Integer) == literal(user_profile.id),
            text(UserMessage.where_unread())
        )
        .select_from(
            join(
                table("zerver_usermessage"),
                table("zerver_message"),
                column("message_id", Integer) == literal_column("zerver_message.id", Integer),
            )
        )
        .group_by(
            column("recipient_id", Integer)
        )
    ).cte("u")

    query: SelectBase = (
        select(
            column("message_id", Integer),
            column("flags", Integer),
            column("unread", Integer),
            literal_column("m.recipient_id", Integer)
        )
        .where(
            ~select(literal_column("1", Integer))
            .where(
                literal_column("s.user_profile_id", Integer)
                == literal_column("m.user_profile_id", Integer),
                literal_column("s.recipient_id", Integer)
                == literal_column("m.recipient_id", Integer),
                or_(
                    not_(literal_column("s.active", Boolean)),
                    not_(literal_column("s.is_user_active", Boolean))
                )
            )
            .select_from(
                table("zerver_subscription").alias("s")
            )
            .exists()
        )
        .select_from(
            outerjoin(
                last_messages_cte,
                unread_cte,
                literal_column("m.recipient_id", Integer) == literal_column("u.recipient_id", Integer)
            )
        )
        .order_by(column("message_id", Integer).desc())
    )

    with get_sqlalchemy_connection() as sa_conn:
        # This is a hack to tag the query we use for testing
        query = query.prefix_with("/* get_messages_overview */")
        rows = list(sa_conn.execute(query).fetchall())

    message_ids: List[int] = []
    user_message_flags: Dict[int, List[str]] = {}
    unread_by_recipient: Dict[int, int] = {}
    for row in rows:
        message_id = row[0]
        flags = row[1]
        user_message_flags[message_id] = UserMessage.flags_list_for_flags(flags)
        message_ids.append(message_id)

        unread = row[2]
        if unread:
            recipient_id = row[3]
            unread_by_recipient[recipient_id] = unread

    message_list = messages_for_ids(
        message_ids=message_ids,
        user_message_flags=user_message_flags,
        search_fields={},
        apply_markdown=apply_markdown,
        client_gravatar=True,
        allow_edit_history=realm.allow_edit_history,
    )

    for message in message_list:
        message["unread"] = unread_by_recipient.get(message["recipient_id"], 0)

    statsd.incr("loaded_old_messages", len(message_list))

    ret = dict(
        messages=message_list,
        result="success",
        msg="",
    )
    return json_success(request, data=ret)
