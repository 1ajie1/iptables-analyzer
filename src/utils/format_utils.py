# -*- coding: utf-8 -*-
"""
格式化工具
提供数据格式转换和美化功能
"""

from typing import Dict, Any, Union
from datetime import datetime
import json


class FormatUtils:
    """格式化工具类，提供数据格式转换和美化功能"""
    
    @staticmethod
    def format_rule_summary(rules_data: Dict[str, Any]) -> str:
        """格式化规则统计摘要"""
        summary_lines = ["iptables规则统计:"]
        
        for table_name, table_data in rules_data.get('iptables_rules', {}).items():
            total_rules = 0
            chain_info = []
            
            for chain_name, chain_data in table_data.items():
                if isinstance(chain_data, dict) and 'rules' in chain_data:
                    rule_count = len(chain_data['rules'])
                    total_rules += rule_count
                    if rule_count > 0:
                        chain_info.append(f"{chain_name}: {rule_count}")
            
            if total_rules > 0:
                chain_str = f" ({', '.join(chain_info)})" if chain_info else ""
                summary_lines.append(f"├── {table_name}表: {total_rules}条规则{chain_str}")
        
        return "\n".join(summary_lines)
    
    @staticmethod
    def format_traffic_result(result: Dict[str, Any], output_format: str = "text") -> str:
        """格式化流量匹配结果"""
        if output_format == "json":
            return json.dumps(result, indent=2, ensure_ascii=False)
        
        elif output_format == "text":
            return FormatUtils._format_text_result(result)
        
        elif output_format == "table":
            return FormatUtils._format_table_result(result)
        
        else:
            raise ValueError(f"不支持的输出格式: {output_format}")
    
    @staticmethod
    def _format_text_result(result: Dict[str, Any]) -> str:
        """格式化文本结果"""
        lines = []
        
        # 流量请求信息
        request = result.get('request', {})
        lines.append("=== 流量匹配结果 ===")
        lines.append(f"源IP: {request.get('src_ip', 'N/A')}")
        lines.append(f"目标IP: {request.get('dst_ip', 'N/A')}")
        lines.append(f"目标端口: {request.get('dst_port', 'N/A')}")
        lines.append(f"协议: {request.get('protocol', 'N/A')}")
        lines.append(f"方向: {request.get('direction', 'N/A')}")
        lines.append("")
        
        # 匹配路径
        lines.append("=== 匹配路径 ===")
        table_results = result.get('table_results', [])
        
        for i, table_result in enumerate(table_results):
            table_name = table_result.get('table_name', 'unknown')
            matched_rules = table_result.get('matched_rules', [])
            final_action = table_result.get('final_action', 'ACCEPT')
            
            lines.append(f"{i+1}. {table_name.upper()}表:")
            
            if matched_rules:
                for rule in matched_rules:
                    rule_id = rule.get('rule_id', 'unknown')
                    action = rule.get('action', 'unknown')
                    conditions = rule.get('match_conditions', {})
                    
                    # 格式化匹配条件
                    condition_str = FormatUtils._format_match_conditions(conditions)
                    lines.append(f"   ├── 规则 {rule_id}: {action} ({condition_str})")
            else:
                lines.append(f"   ├── 未匹配任何规则，执行默认策略: {final_action}")
            
            lines.append("")
        
        # 最终结果
        final_result = result.get('final_result', 'ACCEPT')
        lines.append(f"=== 最终结果: {final_result} ===")
        
        return "\n".join(lines)
    
    @staticmethod
    def _format_match_conditions(conditions: Dict[str, Any]) -> str:
        """格式化匹配条件"""
        condition_parts = []
        
        if conditions.get('source_ip'):
            condition_parts.append(f"源IP={conditions['source_ip']}")
        
        if conditions.get('destination_ip'):
            condition_parts.append(f"目标IP={conditions['destination_ip']}")
        
        if conditions.get('protocol'):
            condition_parts.append(f"协议={conditions['protocol']}")
        
        if conditions.get('source_port'):
            condition_parts.append(f"源端口={conditions['source_port']}")
        
        if conditions.get('destination_port'):
            condition_parts.append(f"目标端口={conditions['destination_port']}")
        
        if conditions.get('in_interface'):
            condition_parts.append(f"入接口={conditions['in_interface']}")
        
        if conditions.get('out_interface'):
            condition_parts.append(f"出接口={conditions['out_interface']}")
        
        return ", ".join(condition_parts) if condition_parts else "无条件"
    
    @staticmethod
    def _format_table_result(result: Dict[str, Any]) -> str:
        """格式化表格结果"""
        # 实现表格格式输出
        pass
    
    @staticmethod
    def format_timestamp(timestamp: Union[str, datetime]) -> str:
        """格式化时间戳"""
        if isinstance(timestamp, str):
            return timestamp
        elif isinstance(timestamp, datetime):
            return timestamp.strftime("%Y-%m-%d %H:%M:%S")
        else:
            return str(timestamp)
    
    @staticmethod
    def format_file_size(size_bytes: int) -> str:
        """格式化文件大小"""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"
