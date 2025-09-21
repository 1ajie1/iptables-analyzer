# -*- coding: utf-8 -*-
"""
nf_tables数据访问对象
从Linux系统获取nf_tables规则，解析为标准格式
使用nftables命令，支持现代netfilter接口，高性能解析
"""

import subprocess
import json
from typing import List, Optional, Any
from src.models.rule_models import IptablesRule, MatchConditions
from src.infrastructure.logger import logger
from src.infrastructure.error_handler import handle_parse_error


class NftablesDAO:
    """nf_tables数据访问对象"""
    
    def __init__(self):
        self.tables = ['raw', 'mangle', 'nat', 'filter']
        self.nft_cmd = 'nft'
        self.family = 'ip'  # 默认使用ip family，可以配置为ip6或inet
        self.timeout = 30   # 命令超时时间
    
    @handle_parse_error
    def get_rules(self, table: Optional[str] = None) -> List[IptablesRule]:
        """获取nf_tables规则
        功能：从系统获取nf_tables规则，支持指定表或全部表
        参数：table-指定表名(filter/nat/mangle/raw)，None表示获取所有表
        返回：IptablesRule对象列表，包含解析后的规则信息
        """
        rules = []
        tables_to_process = [table] if table else self.tables
        
        logger.info(f"开始获取nf_tables规则，表: {tables_to_process}")
        
        for table_name in tables_to_process:
            try:
                table_rules = self._parse_table(table_name)
                rules.extend(table_rules)
                logger.info(f"成功解析表 {table_name}，获得 {len(table_rules)} 条规则")
            except Exception as e:
                logger.error(f"Failed to parse nf_tables table {table_name}: {e}")
                # 继续处理其他表，不中断整个流程
                continue
        
        logger.info(f"nf_tables规则解析完成，总计 {len(rules)} 条规则")
        return rules
    
    def _parse_table(self, table_name: str) -> List[IptablesRule]:
        """解析指定表的规则"""
        rules = []
        
        # 检查表是否存在
        if not self._table_exists(table_name):
            logger.warning(f"表 {table_name} 不存在，跳过")
            return rules
        
        try:
            # 使用nft命令获取JSON格式的规则
            cmd = [self.nft_cmd, '-j', 'list', 'table', self.family, table_name]
            logger.debug(f"执行命令: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                check=True,
                timeout=self.timeout
            )
            
            # 解析JSON输出
            nft_data = json.loads(result.stdout)
            rules = self._parse_nft_json(nft_data, table_name)
            
        except subprocess.TimeoutExpired:
            logger.error(f"nft命令超时: {table_name}")
            raise
        except subprocess.CalledProcessError as e:
            logger.error(f"nft命令执行失败: {e.stderr}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"JSON解析失败: {e}")
            raise
        
        return rules
    
    def _table_exists(self, table_name: str) -> bool:
        """检查表是否存在"""
        try:
            cmd = [self.nft_cmd, 'list', 'tables']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            # 检查输出中是否包含指定表
            expected_table = f"table {self.family} {table_name}"
            return expected_table in result.stdout
            
        except Exception as e:
            logger.warning(f"检查表存在性失败: {e}")
            return True  # 默认假设表存在，让后续命令处理错误
    
    def _parse_nft_json(self, nft_data: dict, table_name: str) -> List[IptablesRule]:
        """解析nftables JSON输出"""
        rules = []
        
        for nft_obj in nft_data.get('nftables', []):
            if 'rule' in nft_obj:
                rule_data = nft_obj['rule']
                parsed_rule = self._parse_nft_rule(rule_data, table_name)
                if parsed_rule:
                    rules.append(parsed_rule)
        
        return rules
    
    def _parse_nft_rule(self, rule_data: dict, table_name: str) -> Optional[IptablesRule]:
        """解析单个nf_tables规则"""
        try:
            # 提取基本信息
            chain_name = rule_data.get('chain', '')
            handle = rule_data.get('handle', 0)
            
            # 生成规则ID
            rule_id = f"{table_name}_{chain_name}_{handle}"
            
            # 提取匹配条件
            match_conditions = self._extract_nft_match_conditions(rule_data)
            
            # 提取动作
            action = self._extract_nft_action(rule_data)
            
            # 提取跳转链和目标
            jump_chain = self._extract_nft_jump_chain(rule_data)
            target = self._extract_nft_target(rule_data)
            
            return IptablesRule(
                rule_id=rule_id,
                match_conditions=match_conditions,
                action=action,
                jump_chain=jump_chain,
                target=target
            )
        except Exception as e:
            logger.error(f"Failed to parse nf_tables rule: {e}")
            logger.debug(f"Rule data: {rule_data}")
            return None
    
    def _extract_nft_match_conditions(self, rule_data: dict) -> MatchConditions:
        """提取nf_tables匹配条件"""
        conditions = MatchConditions()
        
        # 解析表达式列表
        for expr in rule_data.get('expr', []):
            if isinstance(expr, dict):
                self._parse_nft_expression(expr, conditions)
        
        return conditions
    
    def _parse_nft_expression(self, expr: dict, conditions: MatchConditions):
        """解析nf_tables表达式"""
        # 处理match表达式
        if 'match' in expr:
            self._parse_nft_match_expr(expr['match'], conditions)
        
        # 处理payload表达式（协议字段匹配）
        elif 'payload' in expr:
            # payload通常在match的left部分，这里处理独立的payload
            pass
        
        # 处理meta表达式（元数据匹配）
        elif 'meta' in expr:
            # meta通常在match的left部分，这里处理独立的meta
            pass
    
    def _parse_nft_match_expr(self, match_expr: dict, conditions: MatchConditions):
        """解析nf_tables匹配表达式"""
        try:
            left = match_expr.get('left', {})
            right = match_expr.get('right')
            op = match_expr.get('op', '==')
            
            # 处理payload匹配（协议字段）
            if 'payload' in left:
                self._parse_payload_match(left['payload'], right, op, conditions)
            
            # 处理meta匹配（元数据）
            elif 'meta' in left:
                self._parse_meta_match(left['meta'], right, op, conditions)
            
            # 处理其他类型的匹配
            else:
                logger.debug(f"未处理的匹配类型: {left}")
                
        except Exception as e:
            logger.debug(f"解析匹配表达式失败: {e}")
    
    def _parse_payload_match(self, payload: dict, right_value: Any, op: str, conditions: MatchConditions):
        """解析payload匹配（协议字段匹配）"""
        protocol = payload.get('protocol')
        field = payload.get('field')
        
        if protocol == 'ip':
            if field == 'saddr':
                conditions.source_ip = self._format_ip_value(right_value)
            elif field == 'daddr':
                conditions.destination_ip = self._format_ip_value(right_value)
        
        elif protocol == 'tcp':
            conditions.protocol = 'tcp'
            if field == 'sport':
                conditions.source_port = self._format_port_value(right_value)
            elif field == 'dport':
                conditions.destination_port = self._format_port_value(right_value)
        
        elif protocol == 'udp':
            conditions.protocol = 'udp'
            if field == 'sport':
                conditions.source_port = self._format_port_value(right_value)
            elif field == 'dport':
                conditions.destination_port = self._format_port_value(right_value)
        
        elif protocol == 'icmp':
            conditions.protocol = 'icmp'
    
    def _parse_meta_match(self, meta: dict, right_value: Any, op: str, conditions: MatchConditions):
        """解析meta匹配（元数据匹配）"""
        key = meta.get('key')
        
        if key == 'iifname':
            conditions.in_interface = str(right_value) if right_value else None
        elif key == 'oifname':
            conditions.out_interface = str(right_value) if right_value else None
        elif key == 'l4proto':
            # 协议匹配
            if right_value == 6:
                conditions.protocol = 'tcp'
            elif right_value == 17:
                conditions.protocol = 'udp'
            elif right_value == 1:
                conditions.protocol = 'icmp'
            elif isinstance(right_value, str):
                conditions.protocol = right_value
    
    def _format_ip_value(self, value: Any) -> Optional[str]:
        """格式化IP地址值"""
        if isinstance(value, str):
            return value
        elif isinstance(value, dict):
            # 处理prefix格式 {"addr": "192.168.1.0", "len": 24}
            if 'prefix' in value:
                prefix = value['prefix']
                addr = prefix.get('addr')
                length = prefix.get('len')
                if addr and length is not None:
                    return f"{addr}/{length}"
                return addr
            # 处理直接地址格式
            elif 'addr' in value:
                return value['addr']
        return None
    
    def _format_port_value(self, value: Any) -> Optional[int]:
        """格式化端口值"""
        if isinstance(value, int):
            return value
        elif isinstance(value, str) and value.isdigit():
            return int(value)
        return None
    
    def _extract_nft_action(self, rule_data: dict) -> str:
        """提取nf_tables动作"""
        # 遍历表达式，查找动作
        for expr in rule_data.get('expr', []):
            if isinstance(expr, dict):
                # 基本动作
                if 'accept' in expr:
                    return 'ACCEPT'
                elif 'drop' in expr:
                    return 'DROP'
                elif 'reject' in expr:
                    return 'REJECT'
                elif 'return' in expr:
                    return 'RETURN'
                
                # 跳转动作
                elif 'jump' in expr:
                    return 'JUMP'
                elif 'goto' in expr:
                    return 'GOTO'
                
                # xt扩展动作
                elif 'xt' in expr:
                    xt_data = expr['xt']
                    if xt_data.get('type') == 'target':
                        return xt_data.get('name', 'UNKNOWN')
        
        # 默认动作
        return 'CONTINUE'
    
    def _extract_nft_jump_chain(self, rule_data: dict) -> Optional[str]:
        """提取nf_tables跳转链"""
        for expr in rule_data.get('expr', []):
            if isinstance(expr, dict):
                if 'jump' in expr:
                    return expr['jump'].get('target')
                elif 'goto' in expr:
                    return expr['goto'].get('target')
        return None
    
    def _extract_nft_target(self, rule_data: dict) -> Optional[str]:
        """提取nf_tables目标"""
        for expr in rule_data.get('expr', []):
            if isinstance(expr, dict):
                # xt扩展目标
                if 'xt' in expr:
                    xt_data = expr['xt']
                    if xt_data.get('type') == 'target':
                        # 尝试提取目标参数
                        return self._extract_xt_target_params(xt_data)
                
                # NAT目标
                elif 'snat' in expr or 'dnat' in expr:
                    return self._extract_nat_target(expr)
        
        return None
    
    def _extract_xt_target_params(self, xt_data: dict) -> Optional[str]:
        """提取xt扩展目标参数"""
        name = xt_data.get('name', '')
        
        # 这里可以根据具体的xt扩展类型提取参数
        # 例如DNAT、SNAT、MARK等
        if name in ['DNAT', 'SNAT']:
            # 实际的参数提取需要根据nft输出格式来实现
            pass
        
        return name
    
    def _extract_nat_target(self, expr: dict) -> Optional[str]:
        """提取NAT目标"""
        if 'snat' in expr:
            snat_data = expr['snat']
            addr = snat_data.get('addr')
            port = snat_data.get('port')
            if addr:
                return f"{addr}:{port}" if port else addr
        
        elif 'dnat' in expr:
            dnat_data = expr['dnat']
            addr = dnat_data.get('addr')
            port = dnat_data.get('port')
            if addr:
                return f"{addr}:{port}" if port else addr
        
        return None
    
    def set_family(self, family: str):
        """设置协议族"""
        if family in ['ip', 'ip6', 'inet']:
            self.family = family
            logger.info(f"nftables family设置为: {family}")
        else:
            raise ValueError(f"不支持的协议族: {family}")
    
    def set_timeout(self, timeout: int):
        """设置命令超时时间"""
        self.timeout = timeout
        logger.info(f"nftables超时时间设置为: {timeout}秒")
    
    def get_available_tables(self) -> List[str]:
        """获取可用的表列表"""
        try:
            cmd = [self.nft_cmd, 'list', 'tables']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            available_tables = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    # 解析 "table ip filter" 格式
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[0] == 'table' and parts[1] == self.family:
                        available_tables.append(parts[2])
            
            return available_tables
            
        except Exception as e:
            logger.error(f"获取可用表列表失败: {e}")
            return []
