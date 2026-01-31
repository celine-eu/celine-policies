from celine.policies.routes.mqtt import _acc_to_actions


def test_acc_read_only():
    assert _acc_to_actions(1) == ["read"]


def test_acc_publish_only():
    assert _acc_to_actions(2) == ["publish"]


def test_acc_subscribe_only():
    assert _acc_to_actions(4) == ["subscribe"]


def test_acc_read_publish():
    assert _acc_to_actions(3) == ["publish", "read"]


def test_acc_all():
    assert _acc_to_actions(7) == ["subscribe", "publish", "read"]
