from django.conf import settings
import django.contrib.postgres.fields
import django.core.validators
from django.db import migrations, models
import django.db.models.deletion
import zerver_mod.models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("zerver", "0422_multiuseinvite_status"),
    ]

    operations = [
        migrations.CreateModel(
            name="UserGroupMembershipStatus",
            fields=[
                (
                    "membership",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        primary_key=True,
                        related_name="membership_status",
                        serialize=False,
                        to="zerver.usergroupmembership",
                    ),
                ),
                ("status", models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name="UserProfileExt",
            fields=[
                ("id", models.IntegerField(primary_key=True, serialize=False)),
                (
                    "account_type",
                    models.TextField(
                        choices=[
                            ("external", "External account"),
                            ("internal", "Internal account"),
                        ],
                        default="internal",
                    ),
                ),
                (
                    "avatar",
                    models.BinaryField(
                        blank=True,
                        editable=True,
                        null=True,
                        validators=[
                            django.core.validators.MaxLengthValidator(
                                zerver_mod.models._max_avatar_length
                            )
                        ],
                    ),
                ),
                (
                    "name",
                    models.CharField(
                        max_length=98, validators=[django.core.validators.RegexValidator("^\\S+$")]
                    ),
                ),
                (
                    "patronymic",
                    models.CharField(
                        blank=True,
                        default="",
                        max_length=96,
                        validators=[django.core.validators.RegexValidator("^\\S*$")],
                    ),
                ),
                (
                    "permissions",
                    django.contrib.postgres.fields.ArrayField(
                        base_field=models.TextField(),
                        default=zerver_mod.models._default_permissions,
                        size=None,
                    ),
                ),
                (
                    "phone",
                    models.CharField(
                        max_length=10,
                        unique=True,
                        validators=[
                            django.core.validators.MinLengthValidator(10),
                            django.core.validators.RegexValidator("^\\d{10}$"),
                        ],
                    ),
                ),
                (
                    "surname",
                    models.CharField(
                        max_length=98, validators=[django.core.validators.RegexValidator("^\\S+$")]
                    ),
                ),
                (
                    "user_profile",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="+",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="AuthToken",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                ("fcm_token", models.TextField(null=True)),
                ("issued", models.DateTimeField()),
                ("name", models.TextField()),
                (
                    "token",
                    models.CharField(
                        max_length=40,
                        unique=True,
                        validators=[django.core.validators.MinLengthValidator(40)],
                    ),
                ),
                (
                    "user_profile",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="+",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "unique_together": {("user_profile", "name")},
            },
        ),
    ]
