# -*- coding: utf-8 -*-
"""
Mangle表处理器
专门处理mangle表的规则匹配和数据包修改逻辑
主要功能：TOS修改、TTL修改、MARK标记、流量整形
"""

from typing import List, Dict, Any, Optional
from src.processors.base_processor import BaseTableProcessor, ProcessingPhase, ProcessingContext
from src.infrastructure.logger import logger


class MangleTableProcessor(BaseTableProcessor):
    """Mangle表处理器"""
    
    def __init__(self):
        super().__init__("mangle")
        logger.debug("MangleTableProcessor 初始化完成")
    
    def _get_supported_chains(self) -> List[str]:
        """获取mangle表支持的链"""
        return ["PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"]
    
    def _get_processing_order(self) -> List[ProcessingPhase]:
        """获取mangle表的处理顺序"""
        return [
            ProcessingPhase.PREROUTING,
            ProcessingPhase.INPUT,
            ProcessingPhase.FORWARD,
            ProcessingPhase.OUTPUT,
            ProcessingPhase.POSTROUTING
        ]
    
    def _get_chains_for_phase(self, phase: ProcessingPhase) -> List[str]:
        """获取指定阶段需要处理的链"""
        phase_chain_mapping = {
            ProcessingPhase.PREROUTING: ["PREROUTING"],
            ProcessingPhase.INPUT: ["INPUT"],
            ProcessingPhase.FORWARD: ["FORWARD"],
            ProcessingPhase.OUTPUT: ["OUTPUT"],
            ProcessingPhase.POSTROUTING: ["POSTROUTING"]
        }
        return phase_chain_mapping.get(phase, [])
    
    def _handle_rule_action(self, context: ProcessingContext, rule_result: Dict[str, Any]):
        """处理mangle表特定的规则动作"""
        action = rule_result.get('action', 'ACCEPT')
        rule_id = rule_result.get('rule_id', 'unknown')
        target = rule_result.get('target')
        
        if action == 'MARK':
            logger.debug(f"Mangle规则 {rule_id}: 标记数据包 {target}")
            self._apply_mark(context, target)
            
        elif action == 'TOS':
            logger.debug(f"Mangle规则 {rule_id}: 设置TOS字段 {target}")
            self._apply_tos(context, target)
            
        elif action == 'TTL':
            logger.debug(f"Mangle规则 {rule_id}: 修改TTL字段 {target}")
            self._apply_ttl(context, target)
            
        elif action == 'DSCP':
            logger.debug(f"Mangle规则 {rule_id}: 设置DSCP字段 {target}")
            self._apply_dscp(context, target)
            
        elif action == 'TCPMSS':
            logger.debug(f"Mangle规则 {rule_id}: 调整TCP MSS {target}")
            self._apply_tcpmss(context, target)
            
        elif action == 'CLASSIFY':
            logger.debug(f"Mangle规则 {rule_id}: 流量分类 {target}")
            self._apply_classify(context, target)
            
        elif action in ['JUMP', 'GOTO']:
            target_chain = rule_result.get('jump_chain')
            logger.debug(f"Mangle规则 {rule_id}: 跳转到链 {target_chain}")
            
        else:
            logger.debug(f"Mangle规则 {rule_id}: 执行动作 {action}")
    
    def _apply_mark(self, context: ProcessingContext, target: Optional[str]):
        """应用MARK标记"""
        if not target:
            return
        
        try:
            # 解析MARK值，支持格式：value 或 value/mask
            if '/' in target:
                mark_value, mark_mask = target.split('/', 1)
                mark_value = int(mark_value, 0)  # 支持十六进制
                mark_mask = int(mark_mask, 0)
            else:
                mark_value = int(target, 0)
                mark_mask = 0xffffffff
            
            # 记录MARK操作
            context.connection_tracking['mark'] = {
                'value': mark_value,
                'mask': mark_mask,
                'hex_value': hex(mark_value)
            }
            
            context.packet_modified = True
            logger.debug(f"MARK: 设置标记 {hex(mark_value)}")
            
        except ValueError:
            logger.warning(f"无效的MARK值: {target}")
    
    def _apply_tos(self, context: ProcessingContext, target: Optional[str]):
        """应用TOS设置"""
        if not target:
            return
        
        try:
            # TOS值可以是数字或预定义名称
            tos_names = {
                'Minimize-Delay': 0x10,
                'Maximize-Throughput': 0x08,
                'Maximize-Reliability': 0x04,
                'Minimize-Cost': 0x02,
                'Normal-Service': 0x00
            }
            
            if target in tos_names:
                tos_value = tos_names[target]
                tos_name = target
            else:
                tos_value = int(target, 0)
                tos_name = f"0x{tos_value:02x}"
            
            # 记录TOS操作
            context.connection_tracking['tos'] = {
                'value': tos_value,
                'name': tos_name
            }
            
            context.packet_modified = True
            logger.debug(f"TOS: 设置服务类型 {tos_name}")
            
        except ValueError:
            logger.warning(f"无效的TOS值: {target}")
    
    def _apply_ttl(self, context: ProcessingContext, target: Optional[str]):
        """应用TTL修改"""
        if not target:
            return
        
        try:
            # TTL操作格式：set value, inc value, dec value
            if target.startswith('set '):
                operation = 'set'
                value = int(target[4:])
            elif target.startswith('inc '):
                operation = 'increment'
                value = int(target[4:])
            elif target.startswith('dec '):
                operation = 'decrement'
                value = int(target[4:])
            else:
                operation = 'set'
                value = int(target)
            
            # 记录TTL操作
            context.connection_tracking['ttl'] = {
                'operation': operation,
                'value': value
            }
            
            context.packet_modified = True
            logger.debug(f"TTL: {operation} {value}")
            
        except ValueError:
            logger.warning(f"无效的TTL操作: {target}")
    
    def _apply_dscp(self, context: ProcessingContext, target: Optional[str]):
        """应用DSCP设置"""
        if not target:
            return
        
        try:
            # DSCP值或类名
            dscp_classes = {
                'CS0': 0, 'CS1': 8, 'CS2': 16, 'CS3': 24,
                'CS4': 32, 'CS5': 40, 'CS6': 48, 'CS7': 56,
                'AF11': 10, 'AF12': 12, 'AF13': 14,
                'AF21': 18, 'AF22': 20, 'AF23': 22,
                'AF31': 26, 'AF32': 28, 'AF33': 30,
                'AF41': 34, 'AF42': 36, 'AF43': 38,
                'EF': 46
            }
            
            if target in dscp_classes:
                dscp_value = dscp_classes[target]
                dscp_name = target
            else:
                dscp_value = int(target, 0)
                dscp_name = f"0x{dscp_value:02x}"
            
            # 记录DSCP操作
            context.connection_tracking['dscp'] = {
                'value': dscp_value,
                'name': dscp_name
            }
            
            context.packet_modified = True
            logger.debug(f"DSCP: 设置差分服务 {dscp_name}")
            
        except ValueError:
            logger.warning(f"无效的DSCP值: {target}")
    
    def _apply_tcpmss(self, context: ProcessingContext, target: Optional[str]):
        """应用TCP MSS调整"""
        if not target:
            return
        
        try:
            if target == 'pmtu':
                # 使用路径MTU发现
                mss_operation = 'pmtu_discovery'
                mss_value = None
            else:
                # 设置固定MSS值
                mss_operation = 'set_mss'
                mss_value = int(target)
            
            # 记录MSS操作
            context.connection_tracking['tcpmss'] = {
                'operation': mss_operation,
                'value': mss_value
            }
            
            context.packet_modified = True
            logger.debug(f"TCPMSS: {mss_operation} {mss_value or 'auto'}")
            
        except ValueError:
            logger.warning(f"无效的TCPMSS值: {target}")
    
    def _apply_classify(self, context: ProcessingContext, target: Optional[str]):
        """应用流量分类"""
        if not target:
            return
        
        try:
            # 分类ID格式：major:minor
            if ':' in target:
                major, minor = target.split(':', 1)
                class_id = f"{major}:{minor}"
            else:
                class_id = target
            
            # 记录分类操作
            context.connection_tracking['classify'] = {
                'class_id': class_id
            }
            
            context.packet_modified = True
            logger.debug(f"CLASSIFY: 分类到 {class_id}")
            
        except Exception:
            logger.warning(f"无效的CLASSIFY值: {target}")
    
    def _pre_process(self, context: ProcessingContext, result):
        """Mangle表预处理"""
        logger.debug(f"Mangle表预处理开始，阶段: {context.current_phase.value}")
        
        # 初始化连接跟踪
        if not context.connection_tracking:
            context.connection_tracking = {}
        
        traffic = context.traffic_request
        logger.debug(f"处理Mangle数据包: {traffic.source_ip} -> {traffic.destination_ip}")
    
    def _post_process(self, context: ProcessingContext, result):
        """Mangle表后处理"""
        logger.debug(f"Mangle表后处理完成，数据包修改: {context.packet_modified}")
        
        # 记录数据包修改信息到结果中
        if context.connection_tracking:
            modifications = []
            
            if 'mark' in context.connection_tracking:
                mark = context.connection_tracking['mark']
                modifications.append(f"MARK: {mark['hex_value']}")
            
            if 'tos' in context.connection_tracking:
                tos = context.connection_tracking['tos']
                modifications.append(f"TOS: {tos['name']}")
            
            if 'ttl' in context.connection_tracking:
                ttl = context.connection_tracking['ttl']
                modifications.append(f"TTL: {ttl['operation']} {ttl['value']}")
            
            if 'dscp' in context.connection_tracking:
                dscp = context.connection_tracking['dscp']
                modifications.append(f"DSCP: {dscp['name']}")
            
            if 'tcpmss' in context.connection_tracking:
                mss = context.connection_tracking['tcpmss']
                modifications.append(f"TCPMSS: {mss['operation']} {mss['value'] or 'auto'}")
            
            if 'classify' in context.connection_tracking:
                classify = context.connection_tracking['classify']
                modifications.append(f"CLASSIFY: {classify['class_id']}")
            
            # 将修改信息添加到结果中
            if modifications:
                result.jump_results.append({
                    'type': 'packet_modifications',
                    'modifications': modifications
                })
    
    def analyze_mangle_rules(self, table_rules: Dict[str, Any]) -> Dict[str, Any]:
        """分析Mangle规则"""
        analysis = {
            'total_rules': 0,
            'modification_types': {
                'mark_rules': 0,
                'tos_rules': 0,
                'ttl_rules': 0,
                'dscp_rules': 0,
                'tcpmss_rules': 0,
                'classify_rules': 0
            },
            'chain_analysis': {},
            'qos_policies': [],
            'traffic_shaping': []
        }
        
        for chain_name, chain_data in table_rules.items():
            if chain_name not in self.supported_chains:
                continue
            
            rules = chain_data.get('rules', [])
            chain_stats = {
                'rule_count': len(rules),
                'modifications': []
            }
            
            for rule in rules:
                analysis['total_rules'] += 1
                action = rule.get('action', 'ACCEPT')
                target = rule.get('target')
                
                # 统计修改类型
                if action == 'MARK':
                    analysis['modification_types']['mark_rules'] += 1
                elif action == 'TOS':
                    analysis['modification_types']['tos_rules'] += 1
                elif action == 'TTL':
                    analysis['modification_types']['ttl_rules'] += 1
                elif action == 'DSCP':
                    analysis['modification_types']['dscp_rules'] += 1
                elif action == 'TCPMSS':
                    analysis['modification_types']['tcpmss_rules'] += 1
                elif action == 'CLASSIFY':
                    analysis['modification_types']['classify_rules'] += 1
                
                # 记录QoS策略
                if action in ['DSCP', 'TOS', 'CLASSIFY']:
                    analysis['qos_policies'].append({
                        'type': action,
                        'chain': chain_name,
                        'target': target,
                        'rule_id': rule.get('rule_id')
                    })
                
                # 记录流量整形
                if action in ['MARK', 'CLASSIFY']:
                    analysis['traffic_shaping'].append({
                        'type': action,
                        'chain': chain_name,
                        'target': target,
                        'rule_id': rule.get('rule_id')
                    })
                
                # 记录链内修改
                chain_stats['modifications'].append({
                    'action': action,
                    'target': target,
                    'rule_id': rule.get('rule_id')
                })
            
            analysis['chain_analysis'][chain_name] = chain_stats
        
        return analysis
    
    def get_common_patterns(self) -> Dict[str, Dict[str, Any]]:
        """获取常见的Mangle规则模式"""
        return {
            'qos_marking': {
                'description': 'QoS标记',
                'rules': [
                    {
                        'name': 'high_priority_dscp',
                        'chain': 'OUTPUT',
                        'match': {'protocol': 'tcp', 'destination_port': 22},
                        'action': 'DSCP',
                        'target': 'EF',
                        'description': 'SSH流量高优先级标记'
                    },
                    {
                        'name': 'web_traffic_tos',
                        'chain': 'PREROUTING',
                        'match': {'protocol': 'tcp', 'destination_port': 80},
                        'action': 'TOS',
                        'target': 'Maximize-Throughput',
                        'description': 'Web流量吞吐量优化'
                    }
                ]
            },
            'traffic_shaping': {
                'description': '流量整形',
                'rules': [
                    {
                        'name': 'mark_download',
                        'chain': 'PREROUTING',
                        'match': {'in_interface': 'eth0'},
                        'action': 'MARK',
                        'target': '0x1',
                        'description': '下载流量标记'
                    },
                    {
                        'name': 'mark_upload',
                        'chain': 'POSTROUTING',
                        'match': {'out_interface': 'eth0'},
                        'action': 'MARK',
                        'target': '0x2',
                        'description': '上传流量标记'
                    },
                    {
                        'name': 'classify_bulk',
                        'chain': 'POSTROUTING',
                        'match': {'mark': '0x1'},
                        'action': 'CLASSIFY',
                        'target': '1:30',
                        'description': '批量数据分类'
                    }
                ]
            },
            'mss_clamping': {
                'description': 'MSS钳制',
                'rules': [
                    {
                        'name': 'pppoe_mss_clamp',
                        'chain': 'FORWARD',
                        'match': {'protocol': 'tcp', 'tcp_flags': 'SYN'},
                        'action': 'TCPMSS',
                        'target': '1452',
                        'description': 'PPPoE环境MSS调整'
                    },
                    {
                        'name': 'pmtu_discovery',
                        'chain': 'FORWARD',
                        'match': {'protocol': 'tcp'},
                        'action': 'TCPMSS',
                        'target': 'pmtu',
                        'description': '启用路径MTU发现'
                    }
                ]
            }
        }
