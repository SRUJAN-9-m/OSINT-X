import pytest

from utils.validators import (
    ValidationError,
    validate_domain,
    validate_email,
    validate_ip,
    validate_phone,
    validate_url,
    validate_username,
)


def test_valid_username():
    assert validate_username(" john_doe-99 ") == "john_doe-99"


def test_invalid_username():
    with pytest.raises(ValidationError):
        validate_username("has spaces")


def test_valid_email():
    assert validate_email("Person@Example.COM") == "person@example.com"


def test_invalid_email():
    with pytest.raises(ValidationError):
        validate_email("not-an-email")


def test_valid_domain():
    assert validate_domain("https://Example.com/path") == "example.com"


def test_invalid_domain():
    with pytest.raises(ValidationError):
        validate_domain("not a domain")


def test_valid_ip():
    assert validate_ip("8.8.8.8") == "8.8.8.8"


def test_invalid_ip():
    with pytest.raises(ValidationError):
        validate_ip("999.999.999.999")


def test_valid_url():
    assert validate_url("https://example.com/x") == "https://example.com/x"


def test_invalid_url():
    with pytest.raises(ValidationError):
        validate_url("ftp://example.com")


def test_valid_phone():
    assert validate_phone("+1 (555) 123-4567")


def test_invalid_phone():
    with pytest.raises(ValidationError):
        validate_phone("abc")
