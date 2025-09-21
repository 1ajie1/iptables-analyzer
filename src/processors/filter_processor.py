# -*- coding: utf-8 -*-
"""
Filter表处理器
专门处理filter表的规则匹配和流量过滤逻辑
主要功能：数据包过滤、访问控制
"""

from typing import List, Dict, Any
from src.processors.base_processor import BaseTableProcessor, ProcessingPhase, ProcessingContext
from src.infrastructure.logger import logger


class FilterTableProcessor(BaseTableProcessor):
    """Filter表处理器"""
    
    def __init__(self):
        super().__init__("filter")
        logger.debug("FilterTableProcessor 初始化完成")
    
    def _get_supported_chains(self) -> List[str]:
        """获取filter表支持的链"""
        return ["INPUT", "FORWARD", "OUTPUT"]
    
    def _get_processing_order(self) -> List[ProcessingPhase]:
        """获取filter表的处理顺序"""
        return [
            ProcessingPhase.INPUT,
            ProcessingPhase.FORWARD,
            ProcessingPhase.OUTPUT
        ]
    
    def _get_chains_for_phase(self, phase: ProcessingPhase) -> List[str]:
        """获取指定阶段需要处理的链"""
        phase_chain_mapping = {
            ProcessingPhase.INPUT: ["INPUT"],
            ProcessingPhase.FORWARD: ["FORWARD"],
            ProcessingPhase.OUTPUT: ["OUTPUT"]
        }
        return phase_chain_mapping.get(phase, [])
    
    def _handle_rule_action(self, context: ProcessingContext, rule_result: Dict[str, Any]):
        """处理filter表特定的规则动作"""
        action = rule_result.get('action', 'ACCEPT')
        rule_id = rule_result.get('rule_id', 'unknown')
        
        if action == 'ACCEPT':
            logger.debug(f"Filter规则 {rule_id}: 允许数据包通过")
            
        elif action == 'DROP':
            logger.debug(f"Filter规则 {rule_id}: 丢弃数据包")
            
        elif action == 'REJECT':
            logger.debug(f"Filter规则 {rule_id}: 拒绝数据包并发送ICMP响应")
            
        elif action == 'LOG':
            logger.debug(f"Filter规则 {rule_id}: 记录数据包信息")
            # 在实际实现中，这里会记录详细的数据包信息
            
        elif action in ['JUMP', 'GOTO']:
            target_chain = rule_result.get('jump_chain')
            logger.debug(f"Filter规则 {rule_id}: 跳转到链 {target_chain}")
            
        else:
            logger.debug(f"Filter规则 {rule_id}: 执行动作 {action}")
    
    def _pre_process(self, context: ProcessingContext, result):
        """Filter表预处理"""
        logger.debug(f"Filter表预处理开始，阶段: {context.current_phase.value}")
        
        # Filter表的预处理逻辑
        # 例如：检查连接跟踪状态、设置默认策略等
        
        traffic = context.traffic_request
        logger.debug(f"处理数据包: {traffic.source_ip} -> {traffic.destination_ip} ({traffic.protocol})")
    
    def _post_process(self, context: ProcessingContext, result):
        """Filter表后处理"""
        logger.debug(f"Filter表后处理完成，最终动作: {result.final_action}")
        
        # Filter表的后处理逻辑
        # 例如：更新连接跟踪信息、记录统计数据等
        
        if result.final_action == 'DROP':
            logger.info(f"数据包被丢弃: {context.traffic_request.source_ip} -> {context.traffic_request.destination_ip}")
        elif result.final_action == 'REJECT':
            logger.info(f"数据包被拒绝: {context.traffic_request.source_ip} -> {context.traffic_request.destination_ip}")
    
    def analyze_security_rules(self, table_rules: Dict[str, Any]) -> Dict[str, Any]:
        """分析安全规则"""
        analysis = {
            'total_rules': 0,
            'security_rules': {
                'drop_rules': 0,
                'reject_rules': 0,
                'accept_rules': 0,
                'log_rules': 0
            },
            'chain_analysis': {},
            'recommendations': []
        }
        
        for chain_name, chain_data in table_rules.items():
            if chain_name not in self.supported_chains:
                continue
                
            rules = chain_data.get('rules', [])
            chain_stats = {
                'rule_count': len(rules),
                'default_policy': chain_data.get('default_policy', 'ACCEPT'),
                'actions': {}
            }
            
            for rule in rules:
                analysis['total_rules'] += 1
                action = rule.get('action', 'ACCEPT')
                
                # 统计动作类型
                if action == 'DROP':
                    analysis['security_rules']['drop_rules'] += 1
                elif action == 'REJECT':
                    analysis['security_rules']['reject_rules'] += 1
                elif action == 'ACCEPT':
                    analysis['security_rules']['accept_rules'] += 1
                elif action == 'LOG':
                    analysis['security_rules']['log_rules'] += 1
                
                # 统计链内动作
                chain_stats['actions'][action] = chain_stats['actions'].get(action, 0) + 1
            
            analysis['chain_analysis'][chain_name] = chain_stats
        
        # 生成安全建议
        analysis['recommendations'] = self._generate_security_recommendations(analysis)
        
        return analysis
    
    def _generate_security_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """生成安全建议"""
        recommendations = []
        
        # 检查默认策略
        for chain_name, chain_stats in analysis['chain_analysis'].items():
            default_policy = chain_stats.get('default_policy', 'ACCEPT')
            if default_policy == 'ACCEPT' and chain_name in ['INPUT', 'FORWARD']:
                recommendations.append(f"建议将 {chain_name} 链的默认策略设置为 DROP 以提高安全性")
        
        # 检查规则数量
        if analysis['total_rules'] == 0:
            recommendations.append("未发现任何filter规则，建议添加基本的安全规则")
        
        # 检查日志规则
        if analysis['security_rules']['log_rules'] == 0:
            recommendations.append("建议添加LOG规则以便监控可疑流量")
        
        # 检查拒绝规则
        drop_rules = analysis['security_rules']['drop_rules']
        reject_rules = analysis['security_rules']['reject_rules']
        if drop_rules == 0 and reject_rules == 0:
            recommendations.append("建议添加DROP或REJECT规则以阻止恶意流量")
        
        return recommendations
    
    def get_common_patterns(self) -> Dict[str, Dict[str, Any]]:
        """获取常见的filter规则模式"""
        return {
            'basic_security': {
                'description': '基础安全规则',
                'rules': [
                    {
                        'name': 'allow_loopback',
                        'match': {'in_interface': 'lo'},
                        'action': 'ACCEPT',
                        'description': '允许回环接口流量'
                    },
                    {
                        'name': 'allow_established',
                        'match': {'state': 'ESTABLISHED,RELATED'},
                        'action': 'ACCEPT',
                        'description': '允许已建立和相关连接'
                    },
                    {
                        'name': 'drop_invalid',
                        'match': {'state': 'INVALID'},
                        'action': 'DROP',
                        'description': '丢弃无效连接'
                    }
                ]
            },
            'service_protection': {
                'description': '服务保护规则',
                'rules': [
                    {
                        'name': 'limit_ssh',
                        'match': {'protocol': 'tcp', 'destination_port': 22},
                        'action': 'ACCEPT',
                        'description': 'SSH服务访问控制',
                        'options': {'limit': '3/min'}
                    },
                    {
                        'name': 'allow_http',
                        'match': {'protocol': 'tcp', 'destination_port': 80},
                        'action': 'ACCEPT',
                        'description': 'HTTP服务访问'
                    },
                    {
                        'name': 'allow_https',
                        'match': {'protocol': 'tcp', 'destination_port': 443},
                        'action': 'ACCEPT',
                        'description': 'HTTPS服务访问'
                    }
                ]
            },
            'ddos_protection': {
                'description': 'DDoS防护规则',
                'rules': [
                    {
                        'name': 'limit_icmp',
                        'match': {'protocol': 'icmp'},
                        'action': 'ACCEPT',
                        'description': 'ICMP流量限制',
                        'options': {'limit': '1/s'}
                    },
                    {
                        'name': 'limit_new_connections',
                        'match': {'state': 'NEW'},
                        'action': 'ACCEPT',
                        'description': '新连接速率限制',
                        'options': {'limit': '50/s'}
                    }
                ]
            }
        }
