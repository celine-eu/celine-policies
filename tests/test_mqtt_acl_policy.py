"""The shipped `policies/*.rego` bundle, evaluated directly.

`celine/mqtt/acl.rego` and `celine/scopes.rego` are where MQTT authorization
actually lives — the FastAPI layer only decodes a token and a bitmask and hands
them over. Rego is untyped and a rule that silently stops matching (a renamed
helper, a changed `parts` index) does not fail to load; it just returns
`false`, or worse, `true`.

So this file walks the topic grammar and both authority models — service scopes
and user groups — against the real engine. Reasons are asserted alongside
decisions: they are the only diagnostic the broker log carries, and a denial
arriving with the wrong reason means a different rule fired than the one the
test believes it is exercising.
"""

from __future__ import annotations

import pytest

from celine.sdk.policies import (
    Action,
    PolicyInput,
    Resource,
    ResourceType,
    Subject,
    SubjectType,
)

MQTT_ACL = "celine.mqtt.acl"


@pytest.fixture
def decide(policy_engine):
    """Evaluate one MQTT ACL check, returning the Decision."""

    def _decide(
        topic: str,
        action: str = "subscribe",
        *,
        subject_type: SubjectType = SubjectType.SERVICE,
        scopes: list[str] | None = None,
        groups: list[str] | None = None,
    ):
        return policy_engine.evaluate_decision(
            policy_package=MQTT_ACL,
            policy_input=PolicyInput(
                subject=Subject(
                    id="test-subject",
                    type=subject_type,
                    scopes=scopes or [],
                    groups=groups or [],
                ),
                resource=Resource(type=ResourceType.TOPIC, id=topic),
                action=Action(name=action),
            ),
        )

    return _decide


@pytest.fixture
def service(decide):
    """A service subject, authorised only by OAuth scopes."""

    def _service(topic: str, action: str = "subscribe", *scopes: str):
        return decide(
            topic, action, subject_type=SubjectType.SERVICE, scopes=list(scopes)
        )

    return _service


@pytest.fixture
def user(decide):
    """A human subject, authorised only by group membership."""

    def _user(topic: str, action: str = "subscribe", *groups: str):
        return decide(topic, action, subject_type=SubjectType.USER, groups=list(groups))

    return _user


# ---------------------------------------------------------------------------
# The topic grammar: celine/<service>/<resource>/...
# ---------------------------------------------------------------------------


class TestTopicGrammar:
    """The topic *is* the resource identifier, so its parse decides authority.

    `parts[1]` names the service whose scope family applies and `parts[2]` the
    resource. A topic that parsed differently than intended would check the
    wrong scope entirely.
    """

    def test_a_well_formed_topic_checks_service_and_resource(self, service):
        decision = service(
            "celine/pipelines/runs/job-1", "subscribe", "pipelines.runs.read"
        )
        assert decision.allowed is True
        assert decision.reason == "service scope"

    def test_deeper_topics_still_check_the_first_two_segments(self, service):
        """Extra segments carry the instance id; they add no requirement."""
        decision = service(
            "celine/pipelines/runs/2026/08/job-1", "subscribe", "pipelines.runs.read"
        )
        assert decision.allowed is True

    def test_a_topic_outside_the_celine_namespace_is_denied(self, service):
        """No `celine/` prefix, no derived scope — nothing can authorise it."""
        decision = service("other/pipelines/runs", "subscribe", "pipelines.runs.read")
        assert decision.allowed is False
        assert decision.reason == "denied"

    def test_a_scope_matching_the_wrong_service_does_not_apply(self, service):
        decision = service("celine/pipelines/runs/j", "subscribe", "dt.runs.read")
        assert decision.allowed is False

    def test_the_bare_prefix_alone_is_denied(self, service):
        """`celine` has no service segment, so `required` cannot be built."""
        decision = service("celine", "subscribe", "celine.admin", "pipelines.admin")
        assert decision.allowed is False

    def test_a_wildcard_in_the_resource_position_is_rejected(self, service):
        """`celine/<service>/#/...` would span every resource of a service.

        Even an admin scope must not reach it: it is malformed, not broad.
        """
        decision = service("celine/pipelines/#/extra", "subscribe", "pipelines.admin")
        assert decision.allowed is False
        assert decision.reason == "invalid topic format"

    def test_a_plus_in_the_resource_position_is_rejected(self, service):
        decision = service("celine/pipelines/+/extra", "subscribe", "pipelines.admin")
        assert decision.allowed is False
        assert decision.reason == "invalid topic format"

    def test_a_wildcard_deeper_than_the_resource_is_allowed(self, service):
        """`celine/pipelines/runs/+` is the normal way to watch one resource."""
        decision = service("celine/pipelines/runs/+", "subscribe", "pipelines.runs.read")
        assert decision.allowed is True


# ---------------------------------------------------------------------------
# Actions map to verbs, and verbs are what scopes name
# ---------------------------------------------------------------------------


class TestActionToVerbMapping:
    """`subscribe` and `read` are reads; `publish` is a write.

    Collapsing that distinction would let a read-only client publish, which is
    the difference between observing pipeline runs and triggering them.
    """

    @pytest.mark.parametrize("action", ["subscribe", "read"])
    def test_read_actions_need_the_read_scope(self, service, action: str):
        assert (
            service("celine/pipelines/runs/j", action, "pipelines.runs.read").allowed
            is True
        )

    def test_publish_needs_the_write_scope(self, service):
        assert (
            service("celine/pipelines/runs/j", "publish", "pipelines.runs.write").allowed
            is True
        )

    def test_a_read_scope_does_not_grant_publish(self, service):
        assert (
            service("celine/pipelines/runs/j", "publish", "pipelines.runs.read").allowed
            is False
        )

    def test_a_write_scope_does_not_grant_subscribe(self, service):
        """Write-only really is write-only; the grants are not nested."""
        assert (
            service(
                "celine/pipelines/runs/j", "subscribe", "pipelines.runs.write"
            ).allowed
            is False
        )

    @pytest.mark.parametrize("action", ["delete", "write", "", "SUBSCRIBE", "connect"])
    def test_an_unrecognised_action_is_denied(self, service, action: str):
        """Fail closed on an action the policy has no verb for.

        Note the case sensitivity: `SUBSCRIBE` is not `subscribe`.
        """
        decision = service("celine/pipelines/runs/j", action, "pipelines.admin")
        assert decision.allowed is False
        assert decision.reason == "invalid action"


# ---------------------------------------------------------------------------
# Service authority: OAuth scopes
# ---------------------------------------------------------------------------


class TestServiceScopeAuthority:
    def test_an_exact_scope_grants_its_resource_and_verb(self, service):
        assert (
            service("celine/pipelines/runs/j", "subscribe", "pipelines.runs.read").allowed
            is True
        )

    def test_a_resource_wildcard_scope_grants_both_verbs(self, service):
        """`pipelines.runs.*` is the "everything on this resource" grant."""
        assert (
            service("celine/pipelines/runs/j", "subscribe", "pipelines.runs.*").allowed
            is True
        )
        assert (
            service("celine/pipelines/runs/j", "publish", "pipelines.runs.*").allowed
            is True
        )

    def test_a_resource_wildcard_does_not_cross_resources(self, service):
        assert (
            service("celine/pipelines/logs/j", "subscribe", "pipelines.runs.*").allowed
            is False
        )

    def test_a_service_admin_scope_grants_every_resource(self, service):
        assert (
            service("celine/pipelines/anything/j", "publish", "pipelines.admin").allowed
            is True
        )

    def test_a_service_admin_scope_does_not_cross_services(self, service):
        """The blast radius of `pipelines.admin` stops at `celine/pipelines`."""
        assert (
            service("celine/dt/simulation/s", "subscribe", "pipelines.admin").allowed
            is False
        )

    def test_group_membership_does_not_authorise_a_service(self, service, decide):
        """`service_allowed` never consults groups.

        A service token that somehow carried a group claim must not gain from
        it — scopes are the only thing a client credential proves.
        """
        decision = decide(
            "celine/pipelines/runs/j",
            "subscribe",
            subject_type=SubjectType.SERVICE,
            groups=["pipelines.runs.read", "admin"],
        )
        assert decision.allowed is False

    def test_a_service_with_no_scopes_is_denied(self, service):
        assert service("celine/pipelines/runs/j", "subscribe").allowed is False


# ---------------------------------------------------------------------------
# User authority: groups, in both naming conventions
# ---------------------------------------------------------------------------


class TestUserGroupAuthority:
    """Two conventions are supported: dotted, and colon-separated `mqtt:` paths.

    Both are in use — dotted mirrors scope names, `mqtt:` mirrors Keycloak group
    paths — so dropping either would lock out whichever realm uses it.
    """

    def test_a_dotted_group_grants_its_resource_and_verb(self, user):
        decision = user("celine/pipelines/runs/j", "subscribe", "pipelines.runs.read")
        assert decision.allowed is True
        assert decision.reason == "user group"

    def test_an_mqtt_path_group_grants_the_same(self, user):
        assert (
            user(
                "celine/pipelines/runs/j", "subscribe", "mqtt:pipelines:runs:read"
            ).allowed
            is True
        )

    def test_a_dotted_resource_wildcard_group_grants_both_verbs(self, user):
        assert (
            user("celine/pipelines/runs/j", "publish", "pipelines.runs.*").allowed is True
        )

    def test_an_mqtt_path_resource_wildcard_group_grants_both_verbs(self, user):
        assert (
            user("celine/pipelines/runs/j", "publish", "mqtt:pipelines:runs:*").allowed
            is True
        )

    def test_a_read_group_does_not_grant_publish(self, user):
        assert (
            user("celine/pipelines/runs/j", "publish", "pipelines.runs.read").allowed
            is False
        )

    def test_the_admin_group_grants_everything(self, user):
        assert user("celine/dt/simulation/s", "publish", "admin").allowed is True

    def test_the_mqtt_admin_group_grants_everything(self, user):
        assert user("celine/dt/simulation/s", "publish", "mqtt.admin").allowed is True

    @pytest.mark.parametrize("group", ["pipelines.admin", "mqtt:pipelines:admin"])
    def test_a_service_admin_group_grants_one_service(self, user, group: str):
        assert user("celine/pipelines/anything/j", "publish", group).allowed is True

    def test_a_service_admin_group_does_not_cross_services(self, user):
        assert user("celine/dt/simulation/s", "subscribe", "pipelines.admin").allowed is False

    def test_scopes_do_not_authorise_a_user(self, decide):
        """`user_allowed` never consults scopes.

        A browser token carries whatever scopes oauth2-proxy requested, which
        says nothing about what the human may do — that is the group's job.
        """
        decision = decide(
            "celine/pipelines/runs/j",
            "subscribe",
            subject_type=SubjectType.USER,
            scopes=["pipelines.admin", "pipelines.runs.read"],
        )
        assert decision.allowed is False

    def test_an_unrelated_group_grants_nothing(self, user):
        assert user("celine/pipelines/runs/j", "subscribe", "viewers").allowed is False

    def test_a_user_with_no_groups_is_denied(self, user):
        assert user("celine/pipelines/runs/j", "subscribe").allowed is False


# ---------------------------------------------------------------------------
# Broad topics: the whole service, or one wildcard below it
# ---------------------------------------------------------------------------


class TestServiceWideTopics:
    """`celine/<service>` and `celine/<service>/#` see every resource.

    Admin only — a per-resource grant must never widen into them, since one
    subscription would otherwise expose the traffic of every other resource.
    """

    def test_the_service_topic_needs_an_admin_scope(self, service):
        decision = service("celine/pipelines", "subscribe", "pipelines.admin")
        assert decision.allowed is True
        assert decision.reason == "service admin scope"

    def test_a_resource_scope_does_not_open_the_service_topic(self, service):
        assert service("celine/pipelines", "subscribe", "pipelines.runs.read").allowed is False

    @pytest.mark.parametrize("topic", ["celine/pipelines/#", "celine/pipelines/+"])
    def test_a_service_wildcard_needs_an_admin_scope(self, service, topic: str):
        decision = service(topic, "subscribe", "pipelines.admin")
        assert decision.allowed is True
        assert decision.reason == "service admin wildcard"

    @pytest.mark.parametrize("topic", ["celine/pipelines/#", "celine/pipelines/+"])
    def test_a_resource_scope_does_not_open_a_service_wildcard(self, service, topic: str):
        decision = service(topic, "subscribe", "pipelines.runs.read")
        assert decision.allowed is False
        assert decision.reason == "service-level wildcard denied"

    def test_another_services_admin_scope_does_not_open_it(self, service):
        decision = service("celine/pipelines/#", "subscribe", "dt.admin")
        assert decision.allowed is False
        assert decision.reason == "service-level wildcard denied"

    def test_a_user_admin_group_opens_the_service_topic(self, user):
        decision = user("celine/pipelines", "subscribe", "admin")
        assert decision.allowed is True
        assert decision.reason == "user global admin"

    def test_a_user_service_admin_group_opens_the_service_topic(self, user):
        decision = user("celine/pipelines", "subscribe", "pipelines.admin")
        assert decision.allowed is True
        assert decision.reason == "user service admin"

    def test_a_user_admin_group_opens_a_service_wildcard(self, user):
        decision = user("celine/pipelines/#", "publish", "admin")
        assert decision.allowed is True
        assert decision.reason == "user global admin wildcard"

    def test_a_user_service_admin_group_opens_a_service_wildcard(self, user):
        decision = user("celine/pipelines/+", "publish", "pipelines.admin")
        assert decision.allowed is True
        assert decision.reason == "user service admin wildcard"

    def test_a_user_resource_group_does_not_open_a_service_wildcard(self, user):
        decision = user("celine/pipelines/#", "subscribe", "pipelines.runs.read")
        assert decision.allowed is False
        assert decision.reason == "service-level wildcard denied"


# ---------------------------------------------------------------------------
# Fail-closed defaults
# ---------------------------------------------------------------------------


class TestDefaultDeny:
    """Whatever the input, absence of a matching rule must mean deny."""

    def test_an_anonymous_subject_is_denied_everywhere(self, decide):
        for topic in (
            "celine/pipelines/runs/j",
            "celine/pipelines",
            "celine/pipelines/#",
        ):
            decision = decide(topic, "subscribe", subject_type=SubjectType.ANONYMOUS)
            assert decision.allowed is False, topic

    def test_an_anonymous_subject_gains_nothing_from_claims(self, decide):
        """Neither scopes nor groups count until the subject has a type.

        Both `service_allowed` and `user_allowed` gate on `subject.type`, so an
        unauthenticated token carrying an admin scope is still nothing.
        """
        decision = decide(
            "celine/pipelines/runs/j",
            "subscribe",
            subject_type=SubjectType.ANONYMOUS,
            scopes=["pipelines.admin"],
            groups=["admin"],
        )
        assert decision.allowed is False

    def test_a_missing_subject_is_denied(self, policy_engine):
        """The route never sends this, but the policy must not crash or allow."""
        decision = policy_engine.evaluate_decision(
            policy_package=MQTT_ACL,
            policy_input=PolicyInput(
                subject=None,
                resource=Resource(type=ResourceType.TOPIC, id="celine/pipelines/runs/j"),
                action=Action(name="subscribe"),
            ),
        )
        assert decision.allowed is False

    @pytest.mark.parametrize(
        "topic",
        ["", "/", "celine/", "//", "#", "+", "celine//runs/j"],
    )
    def test_degenerate_topics_are_denied(self, service, topic: str):
        """Empty or missing segments must not match a real grant.

        The subject below holds every scope a `svc-pipelines` client actually
        gets. An empty service segment reduces `required` to something like
        `.admin`, which no scope in `clients.yaml` can spell — so these fail
        closed rather than colliding with a legitimate grant.
        """
        decision = service(
            topic,
            "subscribe",
            "pipelines.admin",
            "pipelines.runs.read",
            "pipelines.runs.*",
        )
        assert decision.allowed is False

    def test_an_empty_resource_segment_stays_inside_its_service(self, service):
        """MQTT permits an empty level, so `celine/pipelines//j` is reachable.

        It is still a topic *of* `pipelines`, so the service's admin covers it
        while a resource-scoped grant does not — the service boundary holds,
        which is what matters.
        """
        assert service("celine/pipelines//j", "subscribe", "pipelines.admin").allowed is True
        assert (
            service("celine/pipelines//j", "subscribe", "pipelines.runs.read").allowed
            is False
        )
        assert service("celine/pipelines//j", "subscribe", "dt.admin").allowed is False


# ---------------------------------------------------------------------------
# The bundle itself
# ---------------------------------------------------------------------------


class TestBundleContents:
    def test_both_packages_load(self, policy_engine):
        """`acl.rego` imports `data.celine.scopes`; one without the other denies all."""
        assert policy_engine.has_package("celine.mqtt.acl")
        assert policy_engine.has_package("celine.scopes")

    def test_the_package_the_service_queries_by_default_exists(self, policy_engine):
        """`MqttAuthSettings.mqtt_policy_package` must name a loaded package."""
        from celine.mqtt_auth.config import MqttAuthSettings

        assert policy_engine.has_package(MqttAuthSettings().mqtt_policy_package)
