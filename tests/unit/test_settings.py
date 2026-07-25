"""Unit tests for src/config/settings.py"""

import os
from unittest.mock import patch
import pytest
from src.config.settings import AppConfig, ConfigurationError, load_config

VALID_ENV: dict[str, str] = {
    "AWS_ACCOUNT_ID_EU": "111111111111",
    "AWS_ACCOUNT_ID_APAC": "222222222222",
    "AWS_ACCOUNT_ID_US": "333333333333",
    "AWS_ORG_ID": "o-abc123",
    "AWS_MANAGEMENT_ACCOUNT_ID": "000000000000",
    "SIEM_ENDPOINT": "https://siem.example.com",
    "DPO_PORTAL_ENDPOINT": "https://dpo.example.com",
    "CLOUDTRAIL_LOG_GROUP": "/cloudtrail/logs",
    "VPC_FLOW_LOG_GROUP": "/vpc/flowlogs",
    "CONFIG_AGGREGATOR_NAME": "global-aggregator",
    "ALERT_SNS_TOPIC_ARN": "arn:aws:sns:eu-west-1:111111111111:alerts",
}

class TestLoadConfig:
    def test_returns_app_config_with_valid_env(self):
        with patch.dict(os.environ, VALID_ENV, clear=True):
            result = load_config()
        assert isinstance(result, AppConfig)

    def test_aws_account_ids_populated(self):
        with patch.dict(os.environ, VALID_ENV, clear=True):
            result = load_config()
        assert result.aws.account_id_eu == "111111111111"
        assert result.aws.account_id_apac == "222222222222"
        assert result.aws.account_id_us == "333333333333"

    def test_missing_variable_raises_configuration_error(self):
        # Arrange
        env = {k: v for k, v in VALID_ENV.items() if k != "AWS_ACCOUNT_ID_EU"}
        # Act / Assert
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ConfigurationError) as exc_info:
                load_config()
        assert "AWS_ACCOUNT_ID_EU" in str(exc_info.value)

    def test_empty_variable_raises_configuration_error(self):
        # Arrange
        env = {**VALID_ENV, "AWS_ORG_ID": ""}
        # Act / Assert
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ConfigurationError):
                load_config()

    def test_whitespace_only_variable_raises_configuration_error(self):
        # Arrange
        env = {**VALID_ENV, "SIEM_ENDPOINT": "   "}
        # Act / Assert
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ConfigurationError):
                load_config()

    def test_default_log_level_is_info(self):
        with patch.dict(os.environ, VALID_ENV, clear=True):
            result = load_config()
        assert result.log_level == "INFO"

    def test_config_is_frozen(self):
        with patch.dict(os.environ, VALID_ENV, clear=True):
            result = load_config()
        with pytest.raises(Exception):
            result.log_level = "DEBUG"

    def test_error_message_references_env_example(self):
        # Arrange
        env = {k: v for k, v in VALID_ENV.items() if k != "AWS_ACCOUNT_ID_EU"}
        # Act / Assert
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ConfigurationError) as exc_info:
                load_config()
        assert ".env.example" in str(exc_info.value)
