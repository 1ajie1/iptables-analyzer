# -*- coding: utf-8 -*-
"""
数据模型测试
"""

import pytest
from src.models.rule_models import MatchConditions, IptablesRule, ChainData, TableData, RealServer, VirtualService, RuleSet
from src.models.traffic_models import TrafficRequest, TableResult, SimulationResult


class TestMatchConditions:
    """测试匹配条件类"""
    
    def test_match_conditions_creation(self):
        """测试匹配条件创建"""
        conditions = MatchConditions(
            source_ip="192.168.1.0/24",
            destination_ip="10.96.0.10",
            protocol="tcp",
            destination_port=80
        )
        
        assert conditions.source_ip == "192.168.1.0/24"
        assert conditions.destination_ip == "10.96.0.10"
        assert conditions.protocol == "tcp"
        assert conditions.destination_port == 80
        assert conditions.source_port is None
        assert conditions.in_interface is None
        assert conditions.out_interface is None
        assert conditions.state is None


class TestIptablesRule:
    """测试iptables规则类"""
    
    def test_iptables_rule_creation(self):
        """测试iptables规则创建"""
        conditions = MatchConditions(
            source_ip="192.168.1.0/24",
            destination_ip="10.96.0.10",
            protocol="tcp",
            destination_port=80
        )
        
        rule = IptablesRule(
            rule_id="1",
            match_conditions=conditions,
            action="ACCEPT",
            jump_chain="KUBE-SVC-ABCD1234",
            target="10.244.1.10:80"
        )
        
        assert rule.rule_id == "1"
        assert rule.action == "ACCEPT"
        assert rule.jump_chain == "KUBE-SVC-ABCD1234"
        assert rule.target == "10.244.1.10:80"
        assert rule.match_conditions.source_ip == "192.168.1.0/24"


class TestTrafficRequest:
    """测试流量请求类"""
    
    def test_traffic_request_creation(self):
        """测试流量请求创建"""
        request = TrafficRequest(
            src_ip="192.168.1.10",
            dst_ip="10.96.0.10",
            dst_port=80,
            protocol="tcp",
            direction="outbound",
            src_port=12345
        )
        
        assert request.src_ip == "192.168.1.10"
        assert request.dst_ip == "10.96.0.10"
        assert request.dst_port == 80
        assert request.protocol == "tcp"
        assert request.direction == "outbound"
        assert request.src_port == 12345


class TestSimulationResult:
    """测试模拟结果类"""
    
    def test_simulation_result_creation(self):
        """测试模拟结果创建"""
        request = TrafficRequest(
            src_ip="192.168.1.10",
            dst_ip="10.96.0.10",
            dst_port=80,
            protocol="tcp",
            direction="outbound"
        )
        
        result = SimulationResult(
            request=request,
            final_result="ACCEPT"
        )
        
        assert result.request.src_ip == "192.168.1.10"
        assert result.final_result == "ACCEPT"
        assert result.table_results == []
    
    def test_add_table_result(self):
        """测试添加表结果"""
        request = TrafficRequest(
            src_ip="192.168.1.10",
            dst_ip="10.96.0.10",
            dst_port=80,
            protocol="tcp",
            direction="outbound"
        )
        
        result = SimulationResult(request=request)
        
        table_result = TableResult(
            table_name="nat",
            final_action="DNAT"
        )
        
        result.add_table_result(table_result)
        
        assert len(result.table_results) == 1
        assert result.table_results[0].table_name == "nat"
        assert result.table_results[0].final_action == "DNAT"
