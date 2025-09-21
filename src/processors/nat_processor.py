# -*- coding: utf-8 -*-
"""
NAT表处理器
专门处理nat表的规则匹配和地址转换逻辑
主要功能：源地址转换(SNAT)、目标地址转换(DNAT)、端口映射
"""

from typing import List, Dict, Any, Tuple, Optional
from src.processors.base_processor import BaseTableProcessor, ProcessingPhase, ProcessingContext
from src.infrastructure.logger import logger


class NatTableProcessor(BaseTableProcessor):
    """NAT表处理器"""
    
    def __init__(self):
        super().__init__("nat")
        logger.debug("NatTableProcessor 初始化完成")
    
    def _get_supported_chains(self) -> List[str]:
        """获取nat表支持的链"""
        return ["PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"]
    
    def _get_processing_order(self) -> List[ProcessingPhase]:
        """获取nat表的处理顺序"""
        return [
            ProcessingPhase.PREROUTING,
            ProcessingPhase.INPUT,
            ProcessingPhase.OUTPUT,
            ProcessingPhase.POSTROUTING
        ]
    
    def _get_chains_for_phase(self, phase: ProcessingPhase) -> List[str]:
        """获取指定阶段需要处理的链"""
        phase_chain_mapping = {
            ProcessingPhase.PREROUTING: ["PREROUTING"],
            ProcessingPhase.INPUT: ["INPUT"],
            ProcessingPhase.OUTPUT: ["OUTPUT"],
            ProcessingPhase.POSTROUTING: ["POSTROUTING"]
        }
        return phase_chain_mapping.get(phase, [])
    
    def _handle_rule_action(self, context: ProcessingContext, rule_result: Dict[str, Any]):
        """处理nat表特定的规则动作"""
        action = rule_result.get('action', 'ACCEPT')
        rule_id = rule_result.get('rule_id', 'unknown')
        target = rule_result.get('target')
        
        if action == 'SNAT':
            logger.debug(f"NAT规则 {rule_id}: 源地址转换到 {target}")
            self._apply_snat(context, target)
            
        elif action == 'DNAT':
            logger.debug(f"NAT规则 {rule_id}: 目标地址转换到 {target}")
            self._apply_dnat(context, target)
            
        elif action == 'MASQUERADE':
            logger.debug(f"NAT规则 {rule_id}: 地址伪装")
            self._apply_masquerade(context)
            
        elif action == 'REDIRECT':
            logger.debug(f"NAT规则 {rule_id}: 重定向到本地端口 {target}")
            self._apply_redirect(context, target)
            
        elif action in ['JUMP', 'GOTO']:
            target_chain = rule_result.get('jump_chain')
            logger.debug(f"NAT规则 {rule_id}: 跳转到链 {target_chain}")
            
        else:
            logger.debug(f"NAT规则 {rule_id}: 执行动作 {action}")
    
    def _apply_snat(self, context: ProcessingContext, target: Optional[str]):
        """应用源地址转换"""
        if not target:
            return
        
        original_ip = context.traffic_request.source_ip
        
        # 解析目标地址
        new_ip, new_port = self._parse_nat_target(target)
        
        if new_ip:
            # 记录NAT转换
            context.connection_tracking['snat'] = {
                'original_ip': original_ip,
                'original_port': context.traffic_request.source_port,
                'new_ip': new_ip,
                'new_port': new_port
            }
            
            # 标记数据包已修改
            context.packet_modified = True
            
            logger.debug(f"SNAT: {original_ip} -> {new_ip}")
    
    def _apply_dnat(self, context: ProcessingContext, target: Optional[str]):
        """应用目标地址转换"""
        if not target:
            return
        
        original_ip = context.traffic_request.destination_ip
        original_port = context.traffic_request.destination_port
        
        # 解析目标地址
        new_ip, new_port = self._parse_nat_target(target)
        
        if new_ip:
            # 记录NAT转换
            context.connection_tracking['dnat'] = {
                'original_ip': original_ip,
                'original_port': original_port,
                'new_ip': new_ip,
                'new_port': new_port or original_port
            }
            
            # 标记数据包已修改
            context.packet_modified = True
            
            logger.debug(f"DNAT: {original_ip}:{original_port} -> {new_ip}:{new_port or original_port}")
    
    def _apply_masquerade(self, context: ProcessingContext):
        """应用地址伪装"""
        # 地址伪装通常使用出接口的IP地址
        out_interface = context.traffic_request.out_interface
        
        # 记录伪装信息
        context.connection_tracking['masquerade'] = {
            'original_ip': context.traffic_request.source_ip,
            'original_port': context.traffic_request.source_port,
            'out_interface': out_interface
        }
        
        # 标记数据包已修改
        context.packet_modified = True
        
        logger.debug(f"MASQUERADE: {context.traffic_request.source_ip} via {out_interface}")
    
    def _apply_redirect(self, context: ProcessingContext, target: Optional[str]):
        """应用重定向"""
        if not target:
            return
        
        # 解析重定向端口
        try:
            redirect_port = int(target)
            
            # 记录重定向信息
            context.connection_tracking['redirect'] = {
                'original_port': context.traffic_request.destination_port,
                'redirect_port': redirect_port
            }
            
            # 标记数据包已修改
            context.packet_modified = True
            
            logger.debug(f"REDIRECT: port {context.traffic_request.destination_port} -> {redirect_port}")
            
        except ValueError:
            logger.warning(f"无效的重定向端口: {target}")
    
    def _parse_nat_target(self, target: str) -> Tuple[Optional[str], Optional[int]]:
        """解析NAT目标地址"""
        if not target:
            return None, None
        
        try:
            # 支持格式: IP, IP:port, IP:port-port
            if ':' in target:
                ip_part, port_part = target.split(':', 1)
                
                # 处理端口范围
                if '-' in port_part:
                    port_start = int(port_part.split('-')[0])
                    return ip_part, port_start
                else:
                    return ip_part, int(port_part)
            else:
                return target, None
                
        except ValueError:
            logger.warning(f"无法解析NAT目标: {target}")
            return None, None
    
    def _pre_process(self, context: ProcessingContext, result):
        """NAT表预处理"""
        logger.debug(f"NAT表预处理开始，阶段: {context.current_phase.value}")
        
        # 初始化连接跟踪
        if not context.connection_tracking:
            context.connection_tracking = {}
        
        traffic = context.traffic_request
        logger.debug(f"处理NAT数据包: {traffic.source_ip} -> {traffic.destination_ip}")
    
    def _post_process(self, context: ProcessingContext, result):
        """NAT表后处理"""
        logger.debug(f"NAT表后处理完成，数据包修改: {context.packet_modified}")
        
        # 记录NAT转换信息到结果中
        if context.connection_tracking:
            nat_info = []
            
            if 'snat' in context.connection_tracking:
                snat = context.connection_tracking['snat']
                nat_info.append(f"SNAT: {snat['original_ip']} -> {snat['new_ip']}")
            
            if 'dnat' in context.connection_tracking:
                dnat = context.connection_tracking['dnat']
                nat_info.append(f"DNAT: {dnat['original_ip']}:{dnat['original_port']} -> {dnat['new_ip']}:{dnat['new_port']}")
            
            if 'masquerade' in context.connection_tracking:
                masq = context.connection_tracking['masquerade']
                nat_info.append(f"MASQUERADE: {masq['original_ip']} via {masq['out_interface']}")
            
            if 'redirect' in context.connection_tracking:
                redir = context.connection_tracking['redirect']
                nat_info.append(f"REDIRECT: port {redir['original_port']} -> {redir['redirect_port']}")
            
            # 将NAT信息添加到结果中
            if nat_info:
                result.jump_results.append({
                    'type': 'nat_transformations',
                    'transformations': nat_info
                })
    
    def analyze_nat_rules(self, table_rules: Dict[str, Any]) -> Dict[str, Any]:
        """分析NAT规则"""
        analysis = {
            'total_rules': 0,
            'nat_types': {
                'snat_rules': 0,
                'dnat_rules': 0,
                'masquerade_rules': 0,
                'redirect_rules': 0
            },
            'chain_analysis': {},
            'port_mappings': [],
            'ip_mappings': []
        }
        
        for chain_name, chain_data in table_rules.items():
            if chain_name not in self.supported_chains:
                continue
            
            rules = chain_data.get('rules', [])
            chain_stats = {
                'rule_count': len(rules),
                'nat_operations': []
            }
            
            for rule in rules:
                analysis['total_rules'] += 1
                action = rule.get('action', 'ACCEPT')
                target = rule.get('target')
                
                # 统计NAT类型
                if action == 'SNAT':
                    analysis['nat_types']['snat_rules'] += 1
                    if target:
                        analysis['ip_mappings'].append({
                            'type': 'SNAT',
                            'chain': chain_name,
                            'target': target,
                            'rule_id': rule.get('rule_id')
                        })
                elif action == 'DNAT':
                    analysis['nat_types']['dnat_rules'] += 1
                    if target:
                        analysis['ip_mappings'].append({
                            'type': 'DNAT',
                            'chain': chain_name,
                            'target': target,
                            'rule_id': rule.get('rule_id')
                        })
                elif action == 'MASQUERADE':
                    analysis['nat_types']['masquerade_rules'] += 1
                elif action == 'REDIRECT':
                    analysis['nat_types']['redirect_rules'] += 1
                    if target:
                        analysis['port_mappings'].append({
                            'type': 'REDIRECT',
                            'chain': chain_name,
                            'target_port': target,
                            'rule_id': rule.get('rule_id')
                        })
                
                # 记录链内操作
                chain_stats['nat_operations'].append({
                    'action': action,
                    'target': target,
                    'rule_id': rule.get('rule_id')
                })
            
            analysis['chain_analysis'][chain_name] = chain_stats
        
        return analysis
    
    def get_common_patterns(self) -> Dict[str, Dict[str, Any]]:
        """获取常见的NAT规则模式"""
        return {
            'port_forwarding': {
                'description': '端口转发',
                'rules': [
                    {
                        'name': 'web_server_dnat',
                        'chain': 'PREROUTING',
                        'match': {'protocol': 'tcp', 'destination_port': 80},
                        'action': 'DNAT',
                        'target': '192.168.1.100:80',
                        'description': 'HTTP流量转发到内部服务器'
                    },
                    {
                        'name': 'ssh_port_forward',
                        'chain': 'PREROUTING',
                        'match': {'protocol': 'tcp', 'destination_port': 2222},
                        'action': 'DNAT',
                        'target': '192.168.1.100:22',
                        'description': 'SSH端口转发'
                    }
                ]
            },
            'outbound_nat': {
                'description': '出站地址转换',
                'rules': [
                    {
                        'name': 'internet_masquerade',
                        'chain': 'POSTROUTING',
                        'match': {'out_interface': 'eth0'},
                        'action': 'MASQUERADE',
                        'description': '互联网访问地址伪装'
                    },
                    {
                        'name': 'specific_snat',
                        'chain': 'POSTROUTING',
                        'match': {'source_ip': '192.168.1.0/24'},
                        'action': 'SNAT',
                        'target': '10.0.0.1',
                        'description': '特定网段源地址转换'
                    }
                ]
            },
            'load_balancing': {
                'description': '负载均衡',
                'rules': [
                    {
                        'name': 'web_lb_1',
                        'chain': 'PREROUTING',
                        'match': {'protocol': 'tcp', 'destination_port': 80},
                        'action': 'DNAT',
                        'target': '192.168.1.10:80',
                        'description': 'Web服务负载均衡 - 服务器1',
                        'options': {'probability': 0.5}
                    },
                    {
                        'name': 'web_lb_2',
                        'chain': 'PREROUTING',
                        'match': {'protocol': 'tcp', 'destination_port': 80},
                        'action': 'DNAT',
                        'target': '192.168.1.11:80',
                        'description': 'Web服务负载均衡 - 服务器2',
                        'options': {'probability': 0.5}
                    }
                ]
            }
        }
