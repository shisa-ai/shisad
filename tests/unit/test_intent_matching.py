from __future__ import annotations

from shisad.security.intent_matching import has_follow_on_command


def test_has_follow_on_command_ignores_commands_inside_quotes() -> None:
    assert not has_follow_on_command('remember "then list my todos" for later')


def test_has_follow_on_command_handles_escaped_quotes_inside_quotes() -> None:
    assert not has_follow_on_command(r'remember "hello \" then list my todos" for later')


def test_has_follow_on_command_preserves_unclosed_quote_behavior() -> None:
    assert has_follow_on_command('remember "hello" and list my todos')
    assert has_follow_on_command('remember "hello and list my todos')


def test_has_follow_on_command_handles_long_escaped_quote_input() -> None:
    quoted = '"' + (r"\a" * 10_000) + '"'

    assert not has_follow_on_command(f"remember {quoted} for later")
