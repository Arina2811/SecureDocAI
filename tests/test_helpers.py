import pytest
from utils.helpers import mask_value

def test_mask_value():
    assert mask_value("test@example.com") == "te**@example.com"
    assert mask_value("9876543210") == "98******10"
    assert mask_value("123456789012") == "1234****9012"
    assert mask_value("ABCDE1234F") == "AB***1234F"
    assert mask_value("4111222233334444") == "4111********4444"
    assert mask_value("AKIA1234567890") == "AKIA**********"
    assert mask_value("short") == "*****"
    assert mask_value("verylongstringthatneedsmoremasking") == "ve******************************ng"
