# -*- coding: utf-8 -*-
"""
Raw表处理器
专门处理raw表的规则匹配和连接跟踪控制逻辑
主要功能：连接跟踪控制、数据包标记、性能优化
"""

from typing import List, Dict, Any, Optional
from src.processors.base_processor import BaseTableProcessor, ProcessingPhase, ProcessingContext
from src.infrastructure.logger import logger


class RawTableProcessor(BaseTableProcessor):
    """Raw表处理器"""
    
    def __init__(self):
        super().__init__("raw")
        logger.debug("RawTableProcessor 初始化完成")
    
    def _get_supported_chains(self) -> List[str]:
        """获取raw表支持的链"""
        return ["PREROUTING", "OUTPUT"]
    
    def _get_processing_order(self) -> List[ProcessingPhase]:
        """获取raw表的处理顺序"""
        return [
            ProcessingPhase.PREROUTING,
            ProcessingPhase.OUTPUT
        ]
    
    def _get_chains_for_phase(self, phase: ProcessingPhase) -> List[str]:
        """获取指定阶段需要处理的链"""
        phase_chain_mapping = {
            ProcessingPhase.PREROUTING: ["PREROUTING"],
            ProcessingPhase.OUTPUT: ["OUTPUT"]
        }
        return phase_chain_mapping.get(phase, [])
    
    def _handle_rule_action(self, context: ProcessingContext, rule_result: Dict[str, Any]):
        """处理raw表特定的规则动作"""
        action = rule_result.get('action', 'ACCEPT')
        rule_id = rule_result.get('rule_id', 'unknown')
        target = rule_result.get('target')
        
        if action == 'NOTRACK':
            logger.debug(f"Raw规则 {rule_id}: 禁用连接跟踪")
            self._apply_notrack(context)
            
        elif action == 'CT':
            logger.debug(f"Raw规则 {rule_id}: 连接跟踪配置 {target}")
            self._apply_ct_config(context, target)
            
        elif action == 'TRACE':
            logger.debug(f"Raw规则 {rule_id}: 启用数据包跟踪")
            self._apply_trace(context)
            
        elif action == 'MARK':
            logger.debug(f"Raw规则 {rule_id}: 标记数据包 {target}")
            self._apply_mark(context, target)
            
        elif action in ['JUMP', 'GOTO']:
            target_chain = rule_result.get('jump_chain')
            logger.debug(f"Raw规则 {rule_id}: 跳转到链 {target_chain}")
            
        else:
            logger.debug(f"Raw规则 {rule_id}: 执行动作 {action}")
    
    def _apply_notrack(self, context: ProcessingContext):
        """应用NOTRACK动作"""
        # 禁用连接跟踪
        context.connection_tracking['notrack'] = True
        context.packet_modified = True
        
        logger.debug("NOTRACK: 禁用连接跟踪，提高性能")
    
    def _apply_ct_config(self, context: ProcessingContext, target: Optional[str]):
        """应用连接跟踪配置"""
        if not target:
            return
        
        try:
            # 解析CT配置选项
            ct_config = {}
            
            # 支持的CT选项
            if 'zone' in target:
                # 提取zone值
                zone_start = target.find('zone') + 4
                zone_value = target[zone_start:].split()[0].strip()
                ct_config['zone'] = zone_value
            
            if 'mark' in target:
                # 提取mark值
                mark_start = target.find('mark') + 4
                mark_value = target[mark_start:].split()[0].strip()
                ct_config['mark'] = mark_value
            
            if 'helper' in target:
                # 提取helper名称
                helper_start = target.find('helper') + 6
                helper_name = target[helper_start:].split()[0].strip()
                ct_config['helper'] = helper_name
            
            if 'timeout' in target:
                # 提取timeout值
                timeout_start = target.find('timeout') + 7
                timeout_value = target[timeout_start:].split()[0].strip()
                ct_config['timeout'] = timeout_value
            
            # 记录CT配置
            context.connection_tracking['ct_config'] = ct_config
            context.packet_modified = True
            
            logger.debug(f"CT: 配置连接跟踪 {ct_config}")
            
        except Exception as e:
            logger.warning(f"无效的CT配置: {target}, 错误: {e}")
    
    def _apply_trace(self, context: ProcessingContext):
        """应用数据包跟踪"""
        # 启用数据包跟踪
        context.connection_tracking['trace'] = True
        context.packet_modified = True
        
        logger.debug("TRACE: 启用数据包跟踪，用于调试")
    
    def _apply_mark(self, context: ProcessingContext, target: Optional[str]):
        """应用MARK标记（Raw表版本）"""
        if not target:
            return
        
        try:
            # 解析MARK值
            if '/' in target:
                mark_value, mark_mask = target.split('/', 1)
                mark_value = int(mark_value, 0)
                mark_mask = int(mark_mask, 0)
            else:
                mark_value = int(target, 0)
                mark_mask = 0xffffffff
            
            # 记录MARK操作（Raw表在连接跟踪之前）
            context.connection_tracking['raw_mark'] = {
                'value': mark_value,
                'mask': mark_mask,
                'hex_value': hex(mark_value),
                'early_mark': True  # 标记这是在连接跟踪之前的标记
            }
            
            context.packet_modified = True
            logger.debug(f"RAW MARK: 早期标记 {hex(mark_value)}")
            
        except ValueError:
            logger.warning(f"无效的MARK值: {target}")
    
    def _pre_process(self, context: ProcessingContext, result):
        """Raw表预处理"""
        logger.debug(f"Raw表预处理开始，阶段: {context.current_phase.value}")
        
        # Raw表是最早处理的表，初始化连接跟踪状态
        if not context.connection_tracking:
            context.connection_tracking = {}
        
        # 设置连接跟踪初始状态
        context.connection_tracking['conntrack_enabled'] = True
        
        traffic = context.traffic_request
        logger.debug(f"处理Raw数据包: {traffic.source_ip} -> {traffic.destination_ip}")
        
        # Raw表的特殊处理：检查是否需要跳过连接跟踪
        self._check_notrack_conditions(context)
    
    def _check_notrack_conditions(self, context: ProcessingContext):
        """检查是否需要跳过连接跟踪的条件"""
        traffic = context.traffic_request
        
        # 某些类型的流量可能不需要连接跟踪
        # 例如：本地回环流量、广播流量等
        
        if traffic.source_ip == '127.0.0.1' or traffic.destination_ip == '127.0.0.1':
            logger.debug("检测到本地回环流量，可能不需要连接跟踪")
        
        if traffic.destination_ip and (
            traffic.destination_ip.startswith('224.') or  # IPv4组播
            traffic.destination_ip.startswith('239.') or  # IPv4本地组播
            traffic.destination_ip == '255.255.255.255'   # 广播
        ):
            logger.debug("检测到组播/广播流量，可能不需要连接跟踪")
    
    def _post_process(self, context: ProcessingContext, result):
        """Raw表后处理"""
        logger.debug(f"Raw表后处理完成，连接跟踪状态: {context.connection_tracking.get('conntrack_enabled', True)}")
        
        # 记录Raw表的处理结果
        if context.connection_tracking:
            raw_operations = []
            
            if context.connection_tracking.get('notrack'):
                raw_operations.append("NOTRACK: 禁用连接跟踪")
            
            if 'ct_config' in context.connection_tracking:
                ct_config = context.connection_tracking['ct_config']
                config_items = []
                for key, value in ct_config.items():
                    config_items.append(f"{key}={value}")
                raw_operations.append(f"CT: {', '.join(config_items)}")
            
            if context.connection_tracking.get('trace'):
                raw_operations.append("TRACE: 启用数据包跟踪")
            
            if 'raw_mark' in context.connection_tracking:
                mark = context.connection_tracking['raw_mark']
                raw_operations.append(f"RAW MARK: {mark['hex_value']} (早期标记)")
            
            # 将Raw表操作添加到结果中
            if raw_operations:
                result.jump_results.append({
                    'type': 'raw_operations',
                    'operations': raw_operations
                })
        
        # 设置连接跟踪状态供后续表使用
        if context.connection_tracking.get('notrack'):
            logger.info("数据包将跳过连接跟踪")
    
    def analyze_raw_rules(self, table_rules: Dict[str, Any]) -> Dict[str, Any]:
        """分析Raw规则"""
        analysis = {
            'total_rules': 0,
            'operation_types': {
                'notrack_rules': 0,
                'ct_config_rules': 0,
                'trace_rules': 0,
                'mark_rules': 0
            },
            'chain_analysis': {},
            'performance_impact': {},
            'conntrack_exemptions': []
        }
        
        for chain_name, chain_data in table_rules.items():
            if chain_name not in self.supported_chains:
                continue
            
            rules = chain_data.get('rules', [])
            chain_stats = {
                'rule_count': len(rules),
                'operations': []
            }
            
            notrack_count = 0
            
            for rule in rules:
                analysis['total_rules'] += 1
                action = rule.get('action', 'ACCEPT')
                target = rule.get('target')
                match_conditions = rule.get('match_conditions', {})
                
                # 统计操作类型
                if action == 'NOTRACK':
                    analysis['operation_types']['notrack_rules'] += 1
                    notrack_count += 1
                    
                    # 记录连接跟踪豁免
                    analysis['conntrack_exemptions'].append({
                        'chain': chain_name,
                        'rule_id': rule.get('rule_id'),
                        'conditions': match_conditions
                    })
                    
                elif action == 'CT':
                    analysis['operation_types']['ct_config_rules'] += 1
                elif action == 'TRACE':
                    analysis['operation_types']['trace_rules'] += 1
                elif action == 'MARK':
                    analysis['operation_types']['mark_rules'] += 1
                
                # 记录链内操作
                chain_stats['operations'].append({
                    'action': action,
                    'target': target,
                    'rule_id': rule.get('rule_id')
                })
            
            # 计算性能影响
            chain_stats['notrack_ratio'] = (
                notrack_count / len(rules) if rules else 0
            )
            
            analysis['chain_analysis'][chain_name] = chain_stats
        
        # 评估性能影响
        total_notrack = analysis['operation_types']['notrack_rules']
        if total_notrack > 0:
            analysis['performance_impact'] = {
                'conntrack_bypass_rules': total_notrack,
                'estimated_performance_gain': f"{total_notrack * 10}%",  # 简化估算
                'memory_savings': f"{total_notrack * 256}KB"  # 简化估算
            }
        
        return analysis
    
    def get_common_patterns(self) -> Dict[str, Dict[str, Any]]:
        """获取常见的Raw规则模式"""
        return {
            'performance_optimization': {
                'description': '性能优化',
                'rules': [
                    {
                        'name': 'notrack_loopback',
                        'chain': 'PREROUTING',
                        'match': {'in_interface': 'lo'},
                        'action': 'NOTRACK',
                        'description': '跳过本地回环连接跟踪'
                    },
                    {
                        'name': 'notrack_dns',
                        'chain': 'OUTPUT',
                        'match': {'protocol': 'udp', 'destination_port': 53},
                        'action': 'NOTRACK',
                        'description': 'DNS查询跳过连接跟踪'
                    },
                    {
                        'name': 'notrack_ntp',
                        'chain': 'OUTPUT',
                        'match': {'protocol': 'udp', 'destination_port': 123},
                        'action': 'NOTRACK',
                        'description': 'NTP同步跳过连接跟踪'
                    }
                ]
            },
            'conntrack_tuning': {
                'description': '连接跟踪调优',
                'rules': [
                    {
                        'name': 'ct_zone_dmz',
                        'chain': 'PREROUTING',
                        'match': {'in_interface': 'eth1'},
                        'action': 'CT',
                        'target': 'zone 1',
                        'description': 'DMZ区域连接跟踪分区'
                    },
                    {
                        'name': 'ct_helper_ftp',
                        'chain': 'PREROUTING',
                        'match': {'protocol': 'tcp', 'destination_port': 21},
                        'action': 'CT',
                        'target': 'helper ftp',
                        'description': 'FTP连接跟踪助手'
                    },
                    {
                        'name': 'ct_timeout_web',
                        'chain': 'PREROUTING',
                        'match': {'protocol': 'tcp', 'destination_port': 80},
                        'action': 'CT',
                        'target': 'timeout 300',
                        'description': 'Web连接超时设置'
                    }
                ]
            },
            'debugging': {
                'description': '调试和监控',
                'rules': [
                    {
                        'name': 'trace_suspicious',
                        'chain': 'PREROUTING',
                        'match': {'source_ip': '192.168.100.0/24'},
                        'action': 'TRACE',
                        'description': '跟踪可疑网段流量'
                    },
                    {
                        'name': 'mark_external',
                        'chain': 'PREROUTING',
                        'match': {'in_interface': 'eth0'},
                        'action': 'MARK',
                        'target': '0x100',
                        'description': '标记外部流量'
                    }
                ]
            },
            'high_volume_bypass': {
                'description': '高流量旁路',
                'rules': [
                    {
                        'name': 'notrack_backup',
                        'chain': 'PREROUTING',
                        'match': {'protocol': 'tcp', 'destination_port': 873},
                        'action': 'NOTRACK',
                        'description': 'Rsync备份流量跳过跟踪'
                    },
                    {
                        'name': 'notrack_streaming',
                        'chain': 'PREROUTING',
                        'match': {'protocol': 'udp', 'destination_port': '1024:65535'},
                        'action': 'NOTRACK',
                        'description': '流媒体UDP流量跳过跟踪'
                    }
                ]
            }
        }
