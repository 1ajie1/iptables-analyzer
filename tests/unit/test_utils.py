# -*- coding: utf-8 -*-
"""
工具类测试
"""

import pytest
from src.utils.ip_utils import IPUtils
from src.utils.format_utils import FormatUtils


class TestIPUtils:
    """测试IP工具类"""
    
    def test_is_ip_in_network(self):
        """测试IP网段匹配"""
        assert IPUtils.is_ip_in_network("192.168.1.10", "192.168.1.0/24") == True
        assert IPUtils.is_ip_in_network("192.168.2.10", "192.168.1.0/24") == False
        assert IPUtils.is_ip_in_network("10.96.0.10", "10.96.0.0/16") == True
    
    def test_is_valid_ip(self):
        """测试IP地址验证"""
        assert IPUtils.is_valid_ip("192.168.1.1") == True
        assert IPUtils.is_valid_ip("10.96.0.10") == True
        assert IPUtils.is_valid_ip("invalid-ip") == False
        assert IPUtils.is_valid_ip("256.256.256.256") == False
    
    def test_is_valid_network(self):
        """测试网段验证"""
        assert IPUtils.is_valid_network("192.168.1.0/24") == True
        assert IPUtils.is_valid_network("10.96.0.0/16") == True
        assert IPUtils.is_valid_network("invalid-network") == False
        assert IPUtils.is_valid_network("192.168.1.0/33") == False
    
    def test_normalize_ip(self):
        """测试IP地址标准化"""
        assert IPUtils.normalize_ip("192.168.001.001") == "192.168.1.1"
        assert IPUtils.normalize_ip("10.96.0.10") == "10.96.0.10"
    
    def test_is_private_ip(self):
        """测试私有IP检查"""
        assert IPUtils.is_private_ip("192.168.1.1") == True
        assert IPUtils.is_private_ip("10.96.0.10") == True
        assert IPUtils.is_private_ip("8.8.8.8") == False
    
    def test_is_loopback_ip(self):
        """测试回环IP检查"""
        assert IPUtils.is_loopback_ip("127.0.0.1") == True
        assert IPUtils.is_loopback_ip("192.168.1.1") == False


class TestFormatUtils:
    """测试格式化工具类"""
    
    def test_format_rule_summary(self):
        """测试规则统计摘要格式化"""
        rules_data = {
            "iptables_rules": {
                "filter": {
                    "INPUT": {
                        "rules": [
                            {"rule_id": "1", "action": "ACCEPT"},
                            {"rule_id": "2", "action": "ACCEPT"}
                        ],
                        "default_policy": "DROP"
                    },
                    "FORWARD": {
                        "rules": [
                            {"rule_id": "3", "action": "ACCEPT"}
                        ],
                        "default_policy": "DROP"
                    }
                },
                "nat": {
                    "PREROUTING": {
                        "rules": [
                            {"rule_id": "4", "action": "DNAT"}
                        ],
                        "default_policy": "ACCEPT"
                    }
                }
            }
        }
        
        summary = FormatUtils.format_rule_summary(rules_data)
        
        assert "iptables规则统计:" in summary
        assert "filter表: 3条规则" in summary
        assert "nat表: 1条规则" in summary
        assert "INPUT: 2" in summary
        assert "FORWARD: 1" in summary
        assert "PREROUTING: 1" in summary
    
    def test_format_traffic_result_text(self):
        """测试流量结果文本格式化"""
        result = {
            "request": {
                "src_ip": "192.168.1.10",
                "dst_ip": "10.96.0.10",
                "dst_port": 80,
                "protocol": "tcp",
                "direction": "outbound"
            },
            "table_results": [
                {
                    "table_name": "nat",
                    "matched_rules": [
                        {
                            "rule_id": "1",
                            "action": "DNAT",
                            "match_conditions": {
                                "destination_ip": "10.96.0.10",
                                "protocol": "tcp",
                                "destination_port": 80
                            }
                        }
                    ],
                    "final_action": "DNAT"
                }
            ],
            "final_result": "ACCEPT"
        }
        
        formatted = FormatUtils.format_traffic_result(result, "text")
        
        assert "=== 流量匹配结果 ===" in formatted
        assert "源IP: 192.168.1.10" in formatted
        assert "目标IP: 10.96.0.10" in formatted
        assert "目标端口: 80" in formatted
        assert "协议: tcp" in formatted
        assert "方向: outbound" in formatted
        assert "=== 匹配路径 ===" in formatted
        assert "1. NAT表:" in formatted
        assert "规则 1: DNAT" in formatted
        assert "=== 最终结果: ACCEPT ===" in formatted
    
    def test_format_traffic_result_json(self):
        """测试流量结果JSON格式化"""
        result = {
            "request": {
                "src_ip": "192.168.1.10",
                "dst_ip": "10.96.0.10",
                "dst_port": 80,
                "protocol": "tcp",
                "direction": "outbound"
            },
            "table_results": [],
            "final_result": "ACCEPT"
        }
        
        formatted = FormatUtils.format_traffic_result(result, "json")
        
        # 验证JSON格式
        import json
        parsed = json.loads(formatted)
        assert parsed["request"]["src_ip"] == "192.168.1.10"
        assert parsed["final_result"] == "ACCEPT"
    
    def test_format_match_conditions(self):
        """测试匹配条件格式化"""
        conditions = {
            "source_ip": "192.168.1.0/24",
            "destination_ip": "10.96.0.10",
            "protocol": "tcp",
            "destination_port": 80
        }
        
        formatted = FormatUtils._format_match_conditions(conditions)
        
        assert "源IP=192.168.1.0/24" in formatted
        assert "目标IP=10.96.0.10" in formatted
        assert "协议=tcp" in formatted
        assert "目标端口=80" in formatted
    
    def test_format_file_size(self):
        """测试文件大小格式化"""
        assert FormatUtils.format_file_size(1024) == "1.0 KB"
        assert FormatUtils.format_file_size(1024 * 1024) == "1.0 MB"
        assert FormatUtils.format_file_size(1024 * 1024 * 1024) == "1.0 GB"
        assert FormatUtils.format_file_size(512) == "512 B"
