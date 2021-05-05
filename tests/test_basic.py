import pytest
from cisa.cisa import get_ics_threats, get_vulnerability_reports
from config.config import get_software_list, config_parser, config_parser_section


def test_config_parser():
    result = config_parser("misp","url")
    assert len(result) > 0


def test_config_parser_section():
    result = config_parser_section("misp")
    assert len(result) > 0


def test_software_list():
    result = get_software_list()
    assert len(result) > 0


def test_get_ics_threats():
    threats = get_ics_threats()
    assert len(threats) >= 0


def test_get_vulnerability_reports():
    vulns = get_vulnerability_reports()
    assert len(vulns) >= 0
