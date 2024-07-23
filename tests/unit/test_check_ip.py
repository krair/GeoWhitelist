"""
Unit tests for checkIP function of GeoWhitelist
"""
import pytest
from geowhitelist import checkIP
#target = __import__("geowhitelist.py")
#checkIP = target.checkIP


def test_bad_ip():
    data = "123.456.789.012"
    with pytest.raises(ValueError):
        checkIP(data)
