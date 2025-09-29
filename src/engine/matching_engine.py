# -*- coding: utf-8 -*-
"""
匹配引擎实现
模拟数据包在iptables规则中的匹配过程
支持条件匹配、链遍历、跳转处理、结果生成
"""

from typing import List, Dict, Optional, Any, Union
from dataclasses import dataclass
from enum import Enum

from src.models.rule_models import IptablesRule, RuleSet
from src.models.traffic_models import TrafficRequest, SimulationResult
from src.models.nat_models import NATState, NATRule, NATType
from src.engine.connection_manager import ConnectionManager
from src.infrastructure.logger import logger
from src.infrastructure.error_handler import handle_parse_error
from src.utils.ip_utils import IPUtils
from src.utils.error_handlers import  handle_nat_error, handle_connection_error


class MatchResult(Enum):
    """匹配结果枚举"""
    MATCH = "match"          # 匹配成功
    NO_MATCH = "no_match"    # 匹配失败
    PARTIAL = "partial"      # 部分匹配


@dataclass
class RuleMatchInfo:
    """规则匹配信息"""
    rule: IptablesRule
    match_result: MatchResult
    matched_conditions: List[str]
    unmatched_conditions: List[str]
    execution_action: str
    jump_target: Optional[str] = None


@dataclass
class ChainTraversalInfo:
    """链遍历信息"""
    table_name: str
    chain_name: str
    default_policy: str
    rules_processed: List[RuleMatchInfo]
    final_action: str
    jump_history: List[str]


class MatchingEngine:
    """匹配引擎"""
    
    def __init__(self, strict_mode: bool = False, debug_mode: bool = False, 
                 enable_prerouting: bool = True, enable_postrouting: bool = True,
                 enable_nat: bool = True, connection_timeout: int = 300):
        """
        初始化匹配引擎
        
        Args:
            strict_mode: 严格模式，要求所有条件精确匹配
            debug_mode: 调试模式，输出详细匹配过程
            enable_prerouting: 启用PREROUTING链处理
            enable_postrouting: 启用POSTROUTING链处理
            enable_nat: 启用NAT状态跟踪
            connection_timeout: 连接超时时间（秒）
        """
        self.strict_mode = strict_mode
        self.debug_mode = debug_mode
        self.enable_prerouting = enable_prerouting
        self.enable_postrouting = enable_postrouting
        self.enable_nat = enable_nat
        self.connection_timeout = connection_timeout
        self.ip_utils = IPUtils()
        
        # 初始化NAT状态和连接管理
        if self.enable_nat:
            self.nat_state = NATState()
            self.connection_manager = ConnectionManager(
                default_timeout=connection_timeout
            )
        else:
            self.nat_state = None
            self.connection_manager = None
        
        # 匹配统计
        self.match_stats = {
            'total_packets': 0,
            'total_rules_checked': 0,
            'total_matches': 0,
            'chain_traversals': 0,
            'jumps_executed': 0,
            'nat_transformations': 0,
            'connection_tracks': 0
        }
        
        logger.info(f"匹配引擎初始化完成 (strict_mode={strict_mode}, debug_mode={debug_mode}, "
                   f"prerouting={enable_prerouting}, postrouting={enable_postrouting}, "
                   f"nat={enable_nat}, connection_timeout={connection_timeout})")
    
    @handle_parse_error
    def simulate_packet(
        self, 
        traffic_request: TrafficRequest, 
        ruleset: RuleSet,
        direction: str = "INPUT"
    ) -> SimulationResult:
        """
        模拟数据包匹配过程，按照iptables正确的表处理顺序
        
        Args:
            traffic_request: 流量请求对象
            ruleset: 规则集
            direction: 流量方向 (INPUT/OUTPUT/FORWARD)
            
        Returns:
            SimulationResult对象，包含完整的匹配过程和结果
        """
        logger.info(f"开始模拟数据包匹配: {traffic_request.source_ip} -> {traffic_request.destination_ip}, 方向: {direction}")
        
        self.match_stats['total_packets'] += 1
        
        # 初始化模拟结果
        simulation_result = SimulationResult(
            request=traffic_request,
            final_action="ACCEPT",  # 默认动作
            matched_rules=[],
            chain_traversal=[],
            execution_path=[],
            metadata={"direction": direction}
        )
        
        try:
            # 使用新的处理路径逻辑
            processing_path = self._get_processing_path_for_direction(direction)
            
            for table_name, chain_name in processing_path:
                if table_name not in ruleset.iptables_rules:
                    if self.debug_mode:
                        logger.debug(f"跳过不存在的表: {table_name}")
                    continue
                
                if chain_name not in ruleset.iptables_rules[table_name]:
                    if self.debug_mode:
                        logger.debug(f"跳过不存在的链: {table_name}.{chain_name}")
                    continue
                
                # 应用NAT转换（在PREROUTING和POSTROUTING链中）
                if self.enable_nat and chain_name in ["PREROUTING", "POSTROUTING"]:
                    traffic_request = self._apply_nat_transformations(traffic_request, table_name, chain_name)
                
                # 跟踪连接状态
                self._track_connection(traffic_request, table_name, chain_name)
                
                # 处理该表的链
                if self.debug_mode:
                    logger.debug(f"处理{table_name}表的{chain_name}链")
                final_action = self._traverse_chain(
                    traffic_request, 
                    ruleset, 
                    table_name, 
                    chain_name,
                    simulation_result,
                    direction=direction
                )
                if self.debug_mode:
                    logger.debug(f"{table_name}.{chain_name}处理完成，动作: {final_action}")
                
                # 构建该表的执行路径
                self._build_table_execution_path(simulation_result, table_name)
                
                # 根据链类型决定是否继续处理
                if self._is_terminating_chain(chain_name, final_action, table_name):
                    simulation_result.final_action = final_action
                    logger.info(f"数据包在{table_name}.{chain_name}被{final_action}")
                    return simulation_result
            
            simulation_result.final_action = "ACCEPT"
            simulation_result.metadata.update(self._generate_simulation_metadata())
            
            logger.info("数据包模拟完成，最终动作: ACCEPT")
            
        except Exception as e:
            logger.error(f"数据包模拟失败: {e}")
            simulation_result.final_action = "ERROR"
            simulation_result.metadata = {
                'error': str(e),
                'stats': self.match_stats,
                'direction': direction
            }
        
        return simulation_result
    
    def _traverse_chain(
        self, 
        traffic_request: TrafficRequest,
        ruleset: RuleSet,
        table_name: str,
        chain_name: str,
        simulation_result: SimulationResult,
        jump_history: Optional[List[str]] = None,
        direction: Optional[str] = None
    ) -> str:
        """
        遍历指定链中的规则
        
        Args:
            traffic_request: 流量请求
            ruleset: 规则集
            table_name: 表名
            chain_name: 链名
            simulation_result: 模拟结果对象
            jump_history: 跳转历史
            
        Returns:
            最终执行的动作
        """
        if jump_history is None:
            jump_history = []

        # 防止无限循环
        current_chain_key = f"{table_name}.{chain_name}"
        if current_chain_key in jump_history:
            logger.warning(f"检测到链循环: {' -> '.join(jump_history)} -> {current_chain_key}")
            return "RETURN"
        
        jump_history = jump_history + [current_chain_key]
        self.match_stats['chain_traversals'] += 1
        
        if self.debug_mode:
            logger.debug(f"遍历链: {table_name}.{chain_name}")
        
        # 获取链数据
        chain_data = self._get_chain_data(ruleset, table_name, chain_name)
        if not chain_data:
            logger.warning(f"链不存在: {table_name}.{chain_name}")
            # 记录不存在的链到执行路径
            execution_step = f"{table_name}.{chain_name} -> RETURN (链不存在)"
            simulation_result.execution_path.append(execution_step)
            return "RETURN"  # 对于不存在的链，返回RETURN让调用链继续处理
        
        # 初始化链遍历信息
        chain_info = ChainTraversalInfo(
            table_name=table_name,
            chain_name=chain_name,
            default_policy=chain_data.get('default_policy', 'ACCEPT'),
            rules_processed=[],
            final_action=chain_data.get('default_policy', 'ACCEPT'),
            jump_history=jump_history.copy()
        )
        
        # 遍历链中的规则
        rules = chain_data.get('rules', [])
        for rule_dict in rules:
            self.match_stats['total_rules_checked'] += 1
            
            # 构造规则对象
            rule = self._dict_to_rule(rule_dict)
            if not rule:
                continue
            
            # 匹配规则
            match_info = self._match_rule(traffic_request, rule)
            chain_info.rules_processed.append(match_info)
            
            if self.debug_mode:
                logger.debug(f"规则 {rule.rule_id}: {match_info.match_result.value}")
            
            # 如果匹配成功，执行动作
            if match_info.match_result == MatchResult.MATCH:
                self.match_stats['total_matches'] += 1
                simulation_result.matched_rules.append(match_info)
                
                action = match_info.execution_action
                
                # 处理不同的动作
                if action in ['ACCEPT', 'DROP', 'REJECT']:
                    # 终结动作
                    chain_info.final_action = action
                    break
                
                elif action == 'JUMP' and match_info.jump_target:
                    # 跳转到其他链
                    self.match_stats['jumps_executed'] += 1
                    if self.debug_mode:
                        logger.debug(f"跳转到链: {match_info.jump_target}")
                    
                    jump_result = self._handle_chain_jump(
                        traffic_request,
                        ruleset,
                        table_name,
                        match_info.jump_target,
                        simulation_result,
                        jump_history,
                        direction
                    )
                    
                    if self.debug_mode:
                        logger.debug(f"跳转链 {match_info.jump_target} 返回: {jump_result}")
                    
                    # 如果跳转链返回终结动作，使用该动作
                    if jump_result in ['DROP', 'REJECT']:
                        chain_info.final_action = jump_result
                        if self.debug_mode:
                            logger.debug(f"终结动作 {jump_result}，停止处理")
                        break
                    elif jump_result == 'ACCEPT' and self._is_builtin_chain(match_info.jump_target):
                        # 只有跳转到内置链并返回ACCEPT才是真正的终结动作
                        chain_info.final_action = jump_result
                        if self.debug_mode:
                            logger.debug(f"跳转到内置链{match_info.jump_target}返回ACCEPT，停止处理")
                        break
                    # 对于自定义链的ACCEPT或RETURN，继续处理当前链的下一条规则
                    if self.debug_mode:
                        logger.debug(f"继续处理{chain_name}链的下一条规则")
                
                elif action == 'GOTO' and match_info.jump_target:
                    # 跳转到其他链（不返回）
                    self.match_stats['jumps_executed'] += 1
                    return self._traverse_chain(
                        traffic_request, 
                        ruleset, 
                        table_name, 
                        match_info.jump_target,
                        simulation_result,
                        jump_history,
                        direction
                    )
                
                elif action == 'RETURN':
                    # 返回到调用链
                    chain_info.final_action = 'RETURN'
                    break
                
                elif action in ['DNAT', 'SNAT', 'MASQUERADE', 'MARK']:
                    # 修改动作，继续处理
                    if self.debug_mode:
                        logger.debug(f"执行修改动作: {action}")
                    continue
                
                else:
                    # 其他动作，继续处理
                    if self.debug_mode:
                        logger.debug(f"执行动作: {action}")
                    continue
        
        # 记录链遍历信息
        simulation_result.chain_traversal.append(chain_info)
        
        # 不在这里添加执行路径，而是在表处理完成后统一添加
        
        return chain_info.final_action
    
    def _build_table_execution_path(self, simulation_result: SimulationResult, table_name: str) -> None:
        """构建表的执行路径，按照逻辑顺序排列"""
        # 获取该表的所有链遍历信息
        table_chains = [chain for chain in simulation_result.chain_traversal if chain.table_name == table_name]
        
        # 按照链的访问顺序排序（第一个访问的链在前）
        for chain_info in table_chains:
            # 构建详细的执行路径信息
            matched_rules_in_chain = [rule for rule in chain_info.rules_processed if rule.match_result == MatchResult.MATCH]
            if matched_rules_in_chain:
                # 如果有匹配的规则，显示详细信息
                rule_details = []
                for rule_match in matched_rules_in_chain:
                    rule = rule_match.rule
                    details = self._format_rule_details(rule, rule_match.matched_conditions)
                    rule_details.append(details)
                
                execution_step = f"{table_name}.{chain_info.chain_name} -> {chain_info.final_action}"
                if rule_details:
                    execution_step += f" (匹配规则: {'; '.join(rule_details)})"
            else:
                # 没有匹配规则，使用默认策略
                execution_step = f"{table_name}.{chain_info.chain_name} -> {chain_info.final_action} (默认策略)"
            
            simulation_result.execution_path.append(execution_step)
    
    def _get_chain_data(self, ruleset: RuleSet, table_name: str, chain_name: str) -> Optional[Dict[str, Any]]:
        """获取链数据"""
        if table_name not in ruleset.iptables_rules:
            return None
        
        table_data = ruleset.iptables_rules[table_name]
        if chain_name not in table_data:
            return None
        
        return table_data[chain_name]
    
    def _dict_to_rule(self, rule_dict: Dict[str, Any]) -> Optional[IptablesRule]:
        """将字典转换为规则对象"""
        try:
            from src.models.rule_models import MatchConditions
            
            # 构造匹配条件
            match_conditions_dict = rule_dict.get('match_conditions', {})
            match_conditions = MatchConditions(
                source_ip=match_conditions_dict.get('source_ip'),
                destination_ip=match_conditions_dict.get('destination_ip'),
                protocol=match_conditions_dict.get('protocol'),
                source_port=match_conditions_dict.get('source_port'),
                destination_port=match_conditions_dict.get('destination_port'),
                in_interface=match_conditions_dict.get('in_interface'),
                out_interface=match_conditions_dict.get('out_interface'),
                state=match_conditions_dict.get('state')
            )
            
            # 构造规则对象
            rule = IptablesRule(
                rule_id=rule_dict.get('rule_id', ''),
                match_conditions=match_conditions,
                action=rule_dict.get('action', 'ACCEPT'),
                jump_chain=rule_dict.get('jump_chain'),
                target=rule_dict.get('target')
            )
            
            return rule
            
        except Exception as e:
            logger.error(f"规则字典转换失败: {e}")
            return None
    
    def _match_rule(self, traffic_request: TrafficRequest, rule: IptablesRule) -> RuleMatchInfo:
        """
        匹配单个规则
        
        Args:
            traffic_request: 流量请求
            rule: 规则对象
            
        Returns:
            规则匹配信息
        """
        matched_conditions = []
        unmatched_conditions = []
        
        # 检查源IP
        if rule.match_conditions.source_ip:
            if self._match_ip(traffic_request.source_ip, rule.match_conditions.source_ip):
                matched_conditions.append("source_ip")
            else:
                unmatched_conditions.append("source_ip")
        
        # 检查目标IP
        if rule.match_conditions.destination_ip:
            if self._match_ip(traffic_request.destination_ip, rule.match_conditions.destination_ip):
                matched_conditions.append("destination_ip")
            else:
                unmatched_conditions.append("destination_ip")
        
        # 检查协议
        if rule.match_conditions.protocol:
            if self._match_protocol(traffic_request.protocol, rule.match_conditions.protocol):
                matched_conditions.append("protocol")
            else:
                unmatched_conditions.append("protocol")
        
        # 检查源端口
        if rule.match_conditions.source_port:
            if self._match_port(traffic_request.source_port, rule.match_conditions.source_port):
                matched_conditions.append("source_port")
            else:
                unmatched_conditions.append("source_port")
        
        # 检查目标端口
        if rule.match_conditions.destination_port:
            if self._match_port(traffic_request.destination_port, rule.match_conditions.destination_port):
                matched_conditions.append("destination_port")
            else:
                unmatched_conditions.append("destination_port")
        
        # 检查输入接口
        if rule.match_conditions.in_interface:
            if self._match_interface(traffic_request.in_interface, rule.match_conditions.in_interface):
                matched_conditions.append("in_interface")
            else:
                unmatched_conditions.append("in_interface")
        
        # 检查输出接口
        if rule.match_conditions.out_interface:
            if self._match_interface(traffic_request.out_interface, rule.match_conditions.out_interface):
                matched_conditions.append("out_interface")
            else:
                unmatched_conditions.append("out_interface")
        
        # 检查连接状态
        if rule.match_conditions.state:
            if self._match_state(traffic_request.state, rule.match_conditions.state, traffic_request):
                matched_conditions.append("state")
            else:
                unmatched_conditions.append("state")
        
        # 确定匹配结果
        if unmatched_conditions:
            match_result = MatchResult.NO_MATCH
        elif matched_conditions or not self._has_conditions(rule.match_conditions):
            # 有匹配条件或者规则没有任何条件（匹配所有）
            match_result = MatchResult.MATCH
        else:
            match_result = MatchResult.NO_MATCH
        
        # 确定执行动作
        execution_action = rule.action
        jump_target = rule.jump_chain
        
        return RuleMatchInfo(
            rule=rule,
            match_result=match_result,
            matched_conditions=matched_conditions,
            unmatched_conditions=unmatched_conditions,
            execution_action=execution_action,
            jump_target=jump_target
        )
    
    def _has_conditions(self, match_conditions) -> bool:
        """检查规则是否有任何匹配条件"""
        return any([
            match_conditions.source_ip,
            match_conditions.destination_ip,
            match_conditions.protocol,
            match_conditions.source_port,
            match_conditions.destination_port,
            match_conditions.in_interface,
            match_conditions.out_interface,
            match_conditions.state
        ])
    
    def _format_rule_details(self, rule: IptablesRule, matched_conditions: List[str]) -> str:
        """格式化规则详细信息"""
        details = []
        
        # 规则ID
        if rule.rule_id:
            details.append(f"ID:{rule.rule_id}")
        
        # 动作
        details.append(f"动作:{rule.action}")
        
        # 匹配条件
        conditions = []
        if rule.match_conditions.source_ip:
            conditions.append(f"源IP:{rule.match_conditions.source_ip}")
        if rule.match_conditions.destination_ip:
            conditions.append(f"目标IP:{rule.match_conditions.destination_ip}")
        if rule.match_conditions.protocol:
            conditions.append(f"协议:{rule.match_conditions.protocol}")
        if rule.match_conditions.source_port:
            conditions.append(f"源端口:{rule.match_conditions.source_port}")
        if rule.match_conditions.destination_port:
            conditions.append(f"目标端口:{rule.match_conditions.destination_port}")
        if rule.match_conditions.in_interface:
            conditions.append(f"入接口:{rule.match_conditions.in_interface}")
        if rule.match_conditions.out_interface:
            conditions.append(f"出接口:{rule.match_conditions.out_interface}")
        if rule.match_conditions.state:
            conditions.append(f"状态:{rule.match_conditions.state}")
        
        if conditions:
            details.append(f"条件:[{', '.join(conditions)}]")
        
        # 跳转目标
        if rule.jump_chain:
            details.append(f"跳转:{rule.jump_chain}")
        
        return " ".join(details)
    
    def _get_processing_path_for_direction(self, direction: str) -> List[tuple]:
        """根据流量方向获取完整的处理路径（表名，链名）"""
        if direction == "INPUT":
            path = []
            if self.enable_prerouting:
                path.extend([
                    ("raw", "PREROUTING"),
                    ("mangle", "PREROUTING"),
                    ("nat", "PREROUTING")
                ])
            path.extend([
                ("mangle", "INPUT"),
                ("filter", "INPUT")
            ])
            return path
        elif direction == "OUTPUT":
            path = [
                ("raw", "OUTPUT"),
                ("mangle", "OUTPUT"),
                ("nat", "OUTPUT"),
                ("filter", "OUTPUT")
            ]
            if self.enable_postrouting:
                path.extend([
                    ("mangle", "POSTROUTING"),
                    ("nat", "POSTROUTING")
                ])
            return path
        elif direction == "FORWARD":
            path = []
            if self.enable_prerouting:
                path.extend([
                    ("raw", "PREROUTING"),
                    ("mangle", "PREROUTING"),
                    ("nat", "PREROUTING")
                ])
            path.extend([
                ("mangle", "FORWARD"),
                ("filter", "FORWARD")
            ])
            if self.enable_postrouting:
                path.extend([
                    ("mangle", "POSTROUTING"),
                    ("nat", "POSTROUTING")
                ])
            return path
        else:
            # 默认使用简化的INPUT处理
            return [("filter", "INPUT")]

    def _get_table_order_for_direction(self, direction: str) -> List[str]:
        """根据流量方向获取表的处理顺序（向后兼容）"""
        if direction == "INPUT":
            return ["raw", "mangle", "nat", "filter"]
        elif direction == "OUTPUT":
            return ["raw", "mangle", "nat", "filter"]
        elif direction == "FORWARD":
            return ["raw", "mangle", "nat", "filter"]
        else:
            return ["raw", "mangle", "nat", "filter"]
    
    def _get_chain_for_direction(self, direction: str) -> str:
        """根据流量方向获取对应的链名"""
        if direction == "INPUT":
            return "INPUT"
        elif direction == "OUTPUT":
            return "OUTPUT"
        elif direction == "FORWARD":
            return "FORWARD"
        else:
            return "INPUT"
    
    def _is_terminating_chain(self, chain_name: str, action: str, table_name: str = None) -> bool:
        """判断是否为终结链"""
        # 只有filter表中的DROP/REJECT/ACCEPT是终结动作
        if table_name == 'filter' and chain_name in ['INPUT', 'OUTPUT', 'FORWARD']:
            if action in ['DROP', 'REJECT', 'ACCEPT']:
                return True
        
        # PREROUTING和POSTROUTING链的ACCEPT不是终结动作
        if action == 'ACCEPT' and chain_name in ['PREROUTING', 'POSTROUTING']:
            return False
        
        # 其他表的ACCEPT不是终结动作
        if action == 'ACCEPT' and table_name and table_name != 'filter':
            return False
        
        # 其他表的DROP/REJECT不是终结动作，应该继续处理后续表
        if action in ['DROP', 'REJECT'] and table_name and table_name != 'filter':
            return False
        
        return False

    def _is_builtin_chain(self, chain_name: str) -> bool:
        """判断是否为内置链"""
        builtin_chains = {
            "PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"
        }
        return chain_name in builtin_chains

    def _is_chain_in_processing_path(self, chain_name: str, direction: str) -> bool:
        """判断链是否在当前处理路径中"""
        processing_path = self._get_processing_path_for_direction(direction)
        return any(chain == chain_name for _, chain in processing_path)

    def _handle_chain_jump(self, traffic_request: TrafficRequest, ruleset: RuleSet, 
                          current_table: str, jump_target: str, simulation_result: SimulationResult,
                          jump_history: List[str], direction: str) -> str:
        """处理链跳转，考虑表限制"""
        # 自定义链只能在同一个表中跳转
        if not self._is_builtin_chain(jump_target):
            return self._traverse_chain(
                traffic_request, 
                ruleset, 
                current_table,  # 同一表
                jump_target,
                simulation_result,
                jump_history,
                direction
            )
        
        # 内置链跳转需要检查是否在当前处理路径中
        if self._is_chain_in_processing_path(jump_target, direction):
            # 找到目标链所在的表，优先选择当前表之后出现的表
            processing_path = self._get_processing_path_for_direction(direction)
            target_table = None
            current_table_found = False
            
            for table_name, chain_name in processing_path:
                if table_name == current_table:
                    current_table_found = True
                    continue
                if current_table_found and chain_name == jump_target:
                    target_table = table_name
                    break
            
            # 如果当前表之后没有找到，则查找第一个匹配的表
            if not target_table:
                for table_name, chain_name in processing_path:
                    if chain_name == jump_target:
                        target_table = table_name
                        break
            
            if target_table:
                return self._traverse_chain(
                    traffic_request, 
                    ruleset, 
                    target_table,
                    jump_target,
                    simulation_result,
                    jump_history,
                    direction
                )
        
        # 如果无法跳转，返回RETURN
        if self.debug_mode:
            logger.debug(f"无法跳转到链 {jump_target}，返回RETURN")
        return "RETURN"
    
    @handle_nat_error
    def _apply_nat_transformations(self, traffic_request: TrafficRequest, 
                                 table_name: str, chain_name: str) -> Optional[TrafficRequest]:
        """应用NAT转换"""
        if not self.enable_nat or not self.nat_state:
            return traffic_request
        
        # 在PREROUTING链中应用DNAT
        if chain_name == "PREROUTING":
            dnat_rule = self.nat_state.find_matching_dnat_rule(traffic_request)
            if dnat_rule:
                return self._apply_dnat(traffic_request, dnat_rule)
        
        # 在POSTROUTING链中应用SNAT
        elif chain_name == "POSTROUTING":
            snat_rule = self.nat_state.find_matching_snat_rule(traffic_request)
            if snat_rule:
                return self._apply_snat(traffic_request, snat_rule)
        
        return traffic_request
    
    @handle_nat_error
    def _apply_dnat(self, traffic_request: TrafficRequest, dnat_rule: NATRule) -> TrafficRequest:
        """应用DNAT转换"""
        if not self.enable_nat or not self.nat_state:
            return traffic_request
        
        # 创建或更新连接
        connection = self.nat_state.find_existing_connection(traffic_request)
        if not connection:
            connection = self.nat_state.create_connection(traffic_request, dnat_rule)
            self.match_stats['connection_tracks'] += 1
        
        # 应用转换
        if connection.translated_destination_ip:
            traffic_request.destination_ip = connection.translated_destination_ip
        if connection.translated_destination_port:
            traffic_request.destination_port = connection.translated_destination_port
        
        self.match_stats['nat_transformations'] += 1
        
        if self.debug_mode:
            logger.debug(f"应用DNAT转换: {dnat_rule.rule_id}")
        
        return traffic_request
    
    @handle_nat_error
    def _apply_snat(self, traffic_request: TrafficRequest, snat_rule: NATRule) -> TrafficRequest:
        """应用SNAT转换"""
        if not self.enable_nat or not self.nat_state:
            return traffic_request
        
        # 创建或更新连接
        connection = self.nat_state.find_existing_connection(traffic_request)
        if not connection:
            connection = self.nat_state.create_connection(traffic_request, snat_rule)
            self.match_stats['connection_tracks'] += 1
        
        # 应用转换
        if connection.translated_source_ip:
            traffic_request.source_ip = connection.translated_source_ip
        if connection.translated_source_port:
            traffic_request.source_port = connection.translated_source_port
        
        self.match_stats['nat_transformations'] += 1
        
        if self.debug_mode:
            logger.debug(f"应用SNAT转换: {snat_rule.rule_id}")
        
        return traffic_request
    
    @handle_connection_error
    def _track_connection(self, traffic_request: TrafficRequest, 
                         table_name: str, chain_name: str) -> None:
        """跟踪连接状态"""
        if not self.enable_nat or not self.connection_manager:
            return
        
        # 查找相关的NAT规则
        nat_rule = None
        if chain_name == "PREROUTING":
            nat_rule = self.nat_state.find_matching_dnat_rule(traffic_request) if self.nat_state else None
        elif chain_name == "POSTROUTING":
            nat_rule = self.nat_state.find_matching_snat_rule(traffic_request) if self.nat_state else None
        
        # 跟踪连接
        self.connection_manager.track_connection(traffic_request, nat_rule)
        
        if self.debug_mode:
            logger.debug(f"跟踪连接: {traffic_request.source_ip}:{traffic_request.source_port} -> "
                        f"{traffic_request.destination_ip}:{traffic_request.destination_port}")
    
    def add_nat_rule(self, nat_rule: NATRule) -> None:
        """添加NAT规则"""
        if not self.enable_nat or not self.nat_state:
            logger.warning("NAT功能未启用，无法添加NAT规则")
            return
        
        if nat_rule.nat_type in [NATType.SNAT, NATType.MASQUERADE]:
            self.nat_state.add_snat_rule(nat_rule)
            logger.info(f"添加SNAT规则: {nat_rule.rule_id}")
        elif nat_rule.nat_type in [NATType.DNAT, NATType.REDIRECT]:
            self.nat_state.add_dnat_rule(nat_rule)
            logger.info(f"添加DNAT规则: {nat_rule.rule_id}")
    
    def get_nat_stats(self) -> Dict[str, Any]:
        """获取NAT统计信息"""
        if not self.enable_nat or not self.nat_state:
            return {"nat_enabled": False}
        
        stats = self.nat_state.get_connection_stats()
        stats["nat_enabled"] = True
        stats["nat_transformations"] = self.match_stats.get('nat_transformations', 0)
        stats["connection_tracks"] = self.match_stats.get('connection_tracks', 0)
        
        return stats
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """获取连接统计信息"""
        if not self.enable_nat or not self.connection_manager:
            return {"connection_tracking_enabled": False}
        
        stats = self.connection_manager.get_connection_stats()
        stats["connection_tracking_enabled"] = True
        
        return stats
    
    def _match_ip(self, packet_ip: str, rule_ip: str) -> bool:
        """匹配IP地址"""
        try:
            return self.ip_utils.is_ip_in_network(packet_ip, rule_ip)
        except Exception as e:
            if self.debug_mode:
                logger.debug(f"IP匹配失败: {packet_ip} vs {rule_ip}, 错误: {e}")
            return False
    
    def _match_protocol(self, packet_protocol: str, rule_protocol: str) -> bool:
        """匹配协议"""
        if not packet_protocol or not rule_protocol:
            return False
        
        # 协议名称标准化
        packet_proto = packet_protocol.lower()
        rule_proto = rule_protocol.lower()
        
        # 协议号映射
        protocol_map = {
            'tcp': '6',
            'udp': '17',
            'icmp': '1',
            'icmpv6': '58'
        }
        
        # 标准化协议
        packet_proto = protocol_map.get(packet_proto, packet_proto)
        rule_proto = protocol_map.get(rule_proto, rule_proto)
        
        return packet_proto == rule_proto
    
    def _match_port(self, packet_port: Union[int, str], rule_port: Union[int, str]) -> bool:
        """匹配端口"""
        try:
            if packet_port is None or rule_port is None:
                return False
            
            packet_port_num = int(packet_port)
            
            # 处理端口范围
            rule_port_str = str(rule_port)
            if ':' in rule_port_str:
                # 端口范围，如 "80:90"
                start_port, end_port = rule_port_str.split(':', 1)
                return int(start_port) <= packet_port_num <= int(end_port)
            elif '-' in rule_port_str:
                # 端口范围，如 "80-90"
                start_port, end_port = rule_port_str.split('-', 1)
                return int(start_port) <= packet_port_num <= int(end_port)
            else:
                # 单个端口
                return packet_port_num == int(rule_port_str)
        
        except (ValueError, TypeError) as e:
            if self.debug_mode:
                logger.debug(f"端口匹配失败: {packet_port} vs {rule_port}, 错误: {e}")
            return False
    
    def _match_interface(self, packet_interface: str, rule_interface: str) -> bool:
        """匹配网络接口"""
        if not packet_interface or not rule_interface:
            return False
        
        # 支持通配符匹配
        if rule_interface.endswith('+'):
            # 前缀匹配，如 "eth+"
            prefix = rule_interface[:-1]
            return packet_interface.startswith(prefix)
        else:
            # 精确匹配
            return packet_interface == rule_interface
    
    def _match_state(self, packet_state: str, rule_state: str, traffic_request: TrafficRequest = None) -> bool:
        """匹配连接状态"""
        if not packet_state or not rule_state:
            return False
        
        # 连接状态可能是逗号分隔的列表
        packet_states = set(s.strip().upper() for s in packet_state.split(','))
        rule_states = set(s.strip().upper() for s in rule_state.split(','))
        
        # 检查是否有交集
        if packet_states & rule_states:
            return True
        
        # 如果启用了连接跟踪，进行更精确的状态匹配
        if self.enable_nat and self.connection_manager and traffic_request:
            # 检查连接是否已建立
            if "ESTABLISHED" in rule_states and self.connection_manager.is_connection_established(traffic_request):
                return True
            
            # 检查连接是否相关
            if "RELATED" in rule_states and self.connection_manager.is_connection_related(traffic_request):
                return True
        
        return False
    
    def _generate_simulation_metadata(self) -> Dict[str, Any]:
        """生成模拟元数据"""
        return {
            'engine_config': {
                'strict_mode': self.strict_mode,
                'debug_mode': self.debug_mode
            },
            'statistics': self.match_stats.copy(),
            'performance': {
                'rules_per_packet': (
                    self.match_stats['total_rules_checked'] / self.match_stats['total_packets']
                    if self.match_stats['total_packets'] > 0 else 0
                ),
                'match_rate': (
                    self.match_stats['total_matches'] / self.match_stats['total_rules_checked']
                    if self.match_stats['total_rules_checked'] > 0 else 0
                )
            }
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取匹配统计信息"""
        stats = self.match_stats.copy()
        stats.update({
            'engine_config': {
                'strict_mode': self.strict_mode,
                'debug_mode': self.debug_mode
            },
            'performance_metrics': {
                'avg_rules_per_packet': (
                    stats['total_rules_checked'] / stats['total_packets']
                    if stats['total_packets'] > 0 else 0
                ),
                'match_rate': (
                    stats['total_matches'] / stats['total_rules_checked']
                    if stats['total_rules_checked'] > 0 else 0
                ),
                'jump_rate': (
                    stats['jumps_executed'] / stats['total_packets']
                    if stats['total_packets'] > 0 else 0
                )
            }
        })
        return stats
    
    def reset_statistics(self):
        """重置统计信息"""
        self.match_stats = {
            'total_packets': 0,
            'total_rules_checked': 0,
            'total_matches': 0,
            'chain_traversals': 0,
            'jumps_executed': 0
        }
        logger.info("匹配引擎统计信息已重置")
    
    def set_debug_mode(self, debug_mode: bool):
        """设置调试模式"""
        self.debug_mode = debug_mode
        logger.info(f"调试模式设置为: {debug_mode}")
    
    def set_strict_mode(self, strict_mode: bool):
        """设置严格模式"""
        self.strict_mode = strict_mode
        logger.info(f"严格模式设置为: {strict_mode}")
    
    def __str__(self) -> str:
        """字符串表示"""
        return f"MatchingEngine(strict={self.strict_mode}, debug={self.debug_mode})"
    
    def __repr__(self) -> str:
        """详细字符串表示"""
        return (f"MatchingEngine("
                f"strict_mode={self.strict_mode}, "
                f"debug_mode={self.debug_mode}, "
                f"packets_processed={self.match_stats['total_packets']}"
                f")")
