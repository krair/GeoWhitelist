"""
Unit tests for checkIP function of GeoWhitelist
"""
import pytest
from geowhitelist import checkIP


@pytest.mark.parametrize("maybe_ip, expected_result", [
    ("", False),
    ("not an IP", False),
    ("10.0.0.1", True),
    ("6.7.8.9", True),
    (['1.2.3.4', '4.6.7.8'], False),
    (None, False),
])
@pytest.mark.asyncio
async def test_bad_ip(
                      maybe_ip,
                      expected_result,
                      monkeypatch,
                      mocker
                      ):
    mock_access_control = mocker.patch('geowhitelist.accessControl',
                                       return_value=True)
    res = await checkIP(maybe_ip)
    assert res == expected_result
