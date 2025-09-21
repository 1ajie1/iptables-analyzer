# -*- coding: utf-8 -*-
"""
基础表处理器
定义所有表处理器的通用接口和基础功能
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum

from src.models.traffic_models import TrafficRequest, TableResult
from src.models.rule_models import IptablesRule
from src.infrastructure.logger import logger


class ProcessingPhase(Enum):
    """处理阶段枚举"""
    PREROUTING = "PREROUTING"
    INPUT = "INPUT"
    FORWARD = "FORWARD"
    OUTPUT = "OUTPUT"
    POSTROUTING = "POSTROUTING"


class TableType(Enum):
    """表类型枚举"""
    RAW = "raw"
    MANGLE = "mangle"
    NAT = "nat"
    FILTER = "filter"


@dataclass
class ProcessingContext:
    """处理上下文"""
    traffic_request: TrafficRequest
    current_phase: ProcessingPhase
    table_type: TableType
    packet_modified: bool = False
    connection_tracking: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.connection_tracking is None:
            self.connection_tracking = {}


class BaseTableProcessor(ABC):
    """基础表处理器抽象类"""
    
    def __init__(self, table_name: str):
        """
        初始化表处理器
        
        Args:
            table_name: 表名
        """
        self.table_name = table_name
        self.supported_chains = self._get_supported_chains()
        self.processing_order = self._get_processing_order()
        
        logger.debug(f"{self.__class__.__name__} 初始化完成，表: {table_name}")
    
    @abstractmethod
    def _get_supported_chains(self) -> List[str]:
        """获取支持的链列表"""
        pass
    
    @abstractmethod
    def _get_processing_order(self) -> List[ProcessingPhase]:
        """获取处理阶段顺序"""
        pass
    
    def process_traffic(
        self,
        traffic_request: TrafficRequest,
        table_rules: Dict[str, Any],
        phase: ProcessingPhase
    ) -> TableResult:
        """
        处理流量请求
        
        Args:
            traffic_request: 流量请求
            table_rules: 表规则数据
            phase: 处理阶段
            
        Returns:
            表处理结果
        """
        logger.debug(f"开始处理 {self.table_name} 表，阶段: {phase.value}")
        
        # 创建处理上下文
        context = ProcessingContext(
            traffic_request=traffic_request,
            current_phase=phase,
            table_type=TableType(self.table_name)
        )
        
        # 初始化结果
        result = TableResult(
            table_name=self.table_name,
            matched_rules=[],
            final_action="ACCEPT",
            jump_results=[]
        )
        
        try:
            # 预处理
            self._pre_process(context, result)
            
            # 确定要处理的链
            chains_to_process = self._get_chains_for_phase(phase)
            
            # 处理每个链
            for chain_name in chains_to_process:
                if chain_name in table_rules:
                    chain_result = self._process_chain(
                        context, 
                        table_rules[chain_name], 
                        chain_name
                    )
                    
                    # 合并链处理结果
                    self._merge_chain_result(result, chain_result)
                    
                    # 如果遇到终结动作，停止处理
                    if self._is_terminal_action(chain_result.get('action', 'CONTINUE')):
                        result.final_action = chain_result.get('action', 'ACCEPT')
                        break
            
            # 后处理
            self._post_process(context, result)
            
            logger.debug(f"{self.table_name} 表处理完成，最终动作: {result.final_action}")
            
        except Exception as e:
            logger.error(f"{self.table_name} 表处理失败: {e}")
            result.final_action = "ERROR"
        
        return result
    
    def _process_chain(
        self,
        context: ProcessingContext,
        chain_data: Dict[str, Any],
        chain_name: str
    ) -> Dict[str, Any]:
        """
        处理单个链
        
        Args:
            context: 处理上下文
            chain_data: 链数据
            chain_name: 链名
            
        Returns:
            链处理结果
        """
        logger.debug(f"处理链: {self.table_name}.{chain_name}")
        
        chain_result = {
            'chain_name': chain_name,
            'matched_rules': [],
            'action': chain_data.get('default_policy', 'ACCEPT'),
            'modifications': []
        }
        
        # 处理链中的规则
        rules = chain_data.get('rules', [])
        for rule_dict in rules:
            rule_result = self._process_rule(context, rule_dict, chain_name)
            
            if rule_result['matched']:
                chain_result['matched_rules'].append(rule_result)
                
                # 处理规则动作
                action = rule_result.get('action', 'CONTINUE')
                if self._is_terminal_action(action):
                    chain_result['action'] = action
                    break
                elif action in ['JUMP', 'GOTO']:
                    # 处理跳转（简化实现）
                    chain_result['action'] = 'CONTINUE'
                elif self._is_modification_action(action):
                    # 记录修改动作
                    chain_result['modifications'].append({
                        'action': action,
                        'rule_id': rule_result.get('rule_id'),
                        'target': rule_result.get('target')
                    })
                    context.packet_modified = True
        
        return chain_result
    
    def _process_rule(
        self,
        context: ProcessingContext,
        rule_dict: Dict[str, Any],
        chain_name: str
    ) -> Dict[str, Any]:
        """
        处理单个规则
        
        Args:
            context: 处理上下文
            rule_dict: 规则字典
            chain_name: 链名
            
        Returns:
            规则处理结果
        """
        rule_id = rule_dict.get('rule_id', 'unknown')
        match_conditions = rule_dict.get('match_conditions', {})
        action = rule_dict.get('action', 'ACCEPT')
        
        # 检查规则匹配
        matched = self._match_rule_conditions(context.traffic_request, match_conditions)
        
        rule_result = {
            'rule_id': rule_id,
            'chain_name': chain_name,
            'matched': matched,
            'action': action,
            'target': rule_dict.get('target'),
            'jump_chain': rule_dict.get('jump_chain')
        }
        
        if matched:
            logger.debug(f"规则匹配: {rule_id} -> {action}")
            
            # 表特定的规则处理
            self._handle_rule_action(context, rule_result)
        
        return rule_result
    
    def _match_rule_conditions(
        self,
        traffic_request: TrafficRequest,
        match_conditions: Dict[str, Any]
    ) -> bool:
        """
        匹配规则条件
        
        Args:
            traffic_request: 流量请求
            match_conditions: 匹配条件
            
        Returns:
            是否匹配
        """
        # 基础条件匹配逻辑
        # 子类可以重写以实现表特定的匹配逻辑
        
        # 检查源IP
        if match_conditions.get('source_ip'):
            if not self._match_ip(traffic_request.source_ip, match_conditions['source_ip']):
                return False
        
        # 检查目标IP
        if match_conditions.get('destination_ip'):
            if not self._match_ip(traffic_request.destination_ip, match_conditions['destination_ip']):
                return False
        
        # 检查协议
        if match_conditions.get('protocol'):
            if not self._match_protocol(traffic_request.protocol, match_conditions['protocol']):
                return False
        
        # 检查端口
        if match_conditions.get('source_port'):
            if not self._match_port(traffic_request.source_port, match_conditions['source_port']):
                return False
        
        if match_conditions.get('destination_port'):
            if not self._match_port(traffic_request.destination_port, match_conditions['destination_port']):
                return False
        
        # 检查接口
        if match_conditions.get('in_interface'):
            if not self._match_interface(traffic_request.in_interface, match_conditions['in_interface']):
                return False
        
        if match_conditions.get('out_interface'):
            if not self._match_interface(traffic_request.out_interface, match_conditions['out_interface']):
                return False
        
        return True
    
    def _match_ip(self, packet_ip: str, rule_ip: str) -> bool:
        """匹配IP地址"""
        if not packet_ip or not rule_ip:
            return False
        
        try:
            from src.utils.ip_utils import IPUtils
            ip_utils = IPUtils()
            return ip_utils.is_ip_in_network(packet_ip, rule_ip)
        except Exception:
            return packet_ip == rule_ip
    
    def _match_protocol(self, packet_protocol: str, rule_protocol: str) -> bool:
        """匹配协议"""
        if not packet_protocol or not rule_protocol:
            return False
        return packet_protocol.lower() == rule_protocol.lower()
    
    def _match_port(self, packet_port: Optional[int], rule_port: Any) -> bool:
        """匹配端口"""
        if packet_port is None or rule_port is None:
            return False
        
        try:
            if isinstance(rule_port, str) and ':' in rule_port:
                # 端口范围
                start_port, end_port = rule_port.split(':', 1)
                return int(start_port) <= packet_port <= int(end_port)
            else:
                return packet_port == int(rule_port)
        except (ValueError, TypeError):
            return False
    
    def _match_interface(self, packet_interface: Optional[str], rule_interface: str) -> bool:
        """匹配网络接口"""
        if not packet_interface or not rule_interface:
            return False
        
        if rule_interface.endswith('+'):
            # 前缀匹配
            prefix = rule_interface[:-1]
            return packet_interface.startswith(prefix)
        else:
            return packet_interface == rule_interface
    
    @abstractmethod
    def _get_chains_for_phase(self, phase: ProcessingPhase) -> List[str]:
        """获取指定阶段需要处理的链"""
        pass
    
    @abstractmethod
    def _handle_rule_action(self, context: ProcessingContext, rule_result: Dict[str, Any]):
        """处理规则动作（表特定逻辑）"""
        pass
    
    def _pre_process(self, context: ProcessingContext, result: TableResult):
        """预处理（子类可重写）"""
        pass
    
    def _post_process(self, context: ProcessingContext, result: TableResult):
        """后处理（子类可重写）"""
        pass
    
    def _merge_chain_result(self, table_result: TableResult, chain_result: Dict[str, Any]):
        """合并链处理结果"""
        table_result.matched_rules.extend(chain_result.get('matched_rules', []))
        
        # 记录跳转结果
        if chain_result.get('action') not in ['ACCEPT', 'DROP', 'REJECT']:
            table_result.jump_results.append({
                'chain': chain_result.get('chain_name'),
                'action': chain_result.get('action'),
                'modifications': chain_result.get('modifications', [])
            })
    
    def _is_terminal_action(self, action: str) -> bool:
        """判断是否为终结动作"""
        return action in ['ACCEPT', 'DROP', 'REJECT']
    
    def _is_modification_action(self, action: str) -> bool:
        """判断是否为修改动作"""
        return action in ['DNAT', 'SNAT', 'MASQUERADE', 'MARK', 'TOS', 'TTL']
    
    def get_table_info(self) -> Dict[str, Any]:
        """获取表信息"""
        return {
            'table_name': self.table_name,
            'supported_chains': self.supported_chains,
            'processing_order': [phase.value for phase in self.processing_order],
            'processor_class': self.__class__.__name__
        }
    
    def __str__(self) -> str:
        """字符串表示"""
        return f"{self.__class__.__name__}({self.table_name})"
    
    def __repr__(self) -> str:
        """详细字符串表示"""
        return (f"{self.__class__.__name__}("
                f"table_name='{self.table_name}', "
                f"chains={len(self.supported_chains)}"
                f")")
