# -*- coding: utf-8 -*-
"""
CLI演示功能
整合匹配引擎、表处理器等组件，提供完整的流量演示功能
"""

import json
import time
from typing import Dict, Any, Optional, List
from pathlib import Path
from dataclasses import asdict

from rich.console import Console
from rich.tree import Tree
from rich.text import Text
from rich.panel import Panel
from rich.table import Table

from src.engine.matching_engine import MatchingEngine
from src.processors import (
    FilterTableProcessor, NatTableProcessor, 
    MangleTableProcessor, RawTableProcessor, ProcessingPhase
)
from src.models.traffic_models import TrafficRequest, SimulationResult
from src.models.rule_models import RuleSet
from src.services.parser_service import ParserService
from src.infrastructure.logger import logger
from src.infrastructure.error_handler import handle_parse_error


class CLIDemo:
    """CLI演示类"""
    
    def __init__(self, debug_mode: bool = False):
        """初始化演示组件"""
        self.matching_engine = MatchingEngine(debug_mode=debug_mode)
        self.parser_service = ParserService()
        self.console = Console()
        
        # 初始化表处理器
        self.table_processors = {
            'raw': RawTableProcessor(),
            'mangle': MangleTableProcessor(), 
            'nat': NatTableProcessor(),
            'filter': FilterTableProcessor()
        }
        
        # 表处理顺序（按照iptables处理顺序）
        self.table_order = ['raw', 'mangle', 'nat', 'filter']
        
        logger.info("CLI演示组件初始化完成")
    
    @handle_parse_error
    def simulate_traffic(
        self,
        rules_file: Optional[Path] = None,
        traffic_params: Optional[Dict[str, Any]] = None,
        use_real_rules: bool = True,
        detailed_output: bool = True
    ) -> Dict[str, Any]:
        """
        模拟流量匹配过程
        
        Args:
            rules_file: 规则文件路径
            traffic_params: 流量参数
            use_real_rules: 是否使用真实规则
            detailed_output: 是否输出详细信息
            
        Returns:
            演示结果字典
        """
        logger.info("开始流量演示模拟")
        
        # 获取规则集
        ruleset = self._load_ruleset(rules_file, use_real_rules)
        
        # 创建流量请求
        traffic_request = self._create_traffic_request(traffic_params)
        
        # 执行完整的演示流程
        demo_result = self._execute_full_demo(ruleset, traffic_request, detailed_output)
        
        logger.info("流量演示模拟完成")
        return demo_result
    
    def _load_ruleset(self, rules_file: Optional[Path], use_real_rules: bool) -> RuleSet:
        """加载规则集"""
        if use_real_rules:
            logger.info("使用真实规则集")
            return self.parser_service.parse_rules()
        
        elif rules_file and rules_file.exists():
            logger.info(f"从文件加载规则集: {rules_file}")
            with open(rules_file, 'r', encoding='utf-8') as f:
                rules_data = json.load(f)
            
            # 转换为RuleSet对象
            return RuleSet(
                metadata=rules_data.get('metadata', {}),
                iptables_rules=rules_data.get('iptables_rules', {}),
                ipvs_rules=rules_data.get('ipvs_rules', {"virtual_services": []})
            )
        
        else:
            logger.warning("使用默认规则集")
            return RuleSet(
                metadata={"source": "default"},
                iptables_rules={},
                ipvs_rules={"virtual_services": []}
            )
    
    def _create_traffic_request(self, traffic_params: Optional[Dict[str, Any]]) -> TrafficRequest:
        """创建流量请求"""
        if not traffic_params:
            traffic_params = {
                "source_ip": "192.168.1.100",
                "destination_ip": "10.0.0.1", 
                "protocol": "tcp",
                "destination_port": 80,
                "source_port": 12345,
                "in_interface": "eth0",
                "out_interface": "eth1",
                "state": "NEW"
            }
        
        # 处理向后兼容性
        if "src_ip" in traffic_params:
            traffic_params["source_ip"] = traffic_params.pop("src_ip")
        if "dst_ip" in traffic_params:
            traffic_params["destination_ip"] = traffic_params.pop("dst_ip")
        if "dst_port" in traffic_params:
            traffic_params["destination_port"] = traffic_params.pop("dst_port")
        if "src_port" in traffic_params:
            traffic_params["source_port"] = traffic_params.pop("src_port")
        
        return TrafficRequest(**traffic_params)
    
    def _execute_full_demo(
        self, 
        ruleset: RuleSet, 
        traffic_request: TrafficRequest,
        detailed_output: bool
    ) -> Dict[str, Any]:
        """执行完整演示流程"""
        demo_result = {
            "traffic_request": asdict(traffic_request),
            "ruleset_info": {
                "tables": len(ruleset.iptables_rules),
                "total_rules": self._count_total_rules(ruleset)
            },
            "processing_stages": [],
            "matching_engine_result": None,
            "table_processor_results": {},
            "final_decision": "ACCEPT",
            "performance_metrics": {},
            "recommendations": []
        }
        
        start_time = time.time()
        
        # 1. 使用匹配引擎进行完整模拟
        logger.info("执行匹配引擎模拟")
        # 根据流量参数判断方向（简单判断，后续可以改进）
        direction = self._determine_traffic_direction({
            "source_ip": traffic_request.source_ip,
            "destination_ip": traffic_request.destination_ip
        })
        matching_result = self.matching_engine.simulate_packet(traffic_request, ruleset, direction)
        demo_result["matching_engine_result"] = self._format_matching_result(matching_result)
        demo_result["final_decision"] = matching_result.final_action
        
        # 2. 使用表处理器进行分阶段处理
        if detailed_output:
            logger.info("执行表处理器分析")
            table_results = self._process_with_table_processors(ruleset, traffic_request)
            demo_result["table_processor_results"] = table_results
        
        # 3. 生成性能指标
        end_time = time.time()
        demo_result["performance_metrics"] = {
            "total_time_ms": round((end_time - start_time) * 1000, 2),
            "engine_stats": self.matching_engine.get_statistics()
        }
        
        # 4. 生成建议
        demo_result["recommendations"] = self._generate_recommendations(
            matching_result, ruleset, traffic_request
        )
        
        return demo_result
    
    def _count_total_rules(self, ruleset: RuleSet) -> int:
        """统计规则总数"""
        total = 0
        for table_data in ruleset.iptables_rules.values():
            for chain_data in table_data.values():
                if isinstance(chain_data, dict) and 'rules' in chain_data:
                    total += len(chain_data['rules'])
        return total
    
    def _determine_traffic_direction(self, traffic_params: Dict[str, Any]) -> str:
        """根据流量参数判断流量方向"""
        # 简单的判断逻辑，可以根据需要扩展
        src_ip = traffic_params.get("source_ip", "")
        dst_ip = traffic_params.get("destination_ip", "")
        
        # 如果源IP是本地地址，认为是OUTPUT
        if src_ip.startswith("127.") or src_ip == "::1":
            return "OUTPUT"
        
        # 如果目标IP是本地地址，认为是INPUT
        if dst_ip.startswith("127.") or dst_ip == "::1":
            return "INPUT"
        
        # 默认认为是INPUT（外部流量进入）
        return "INPUT"
    
    def _format_matching_result(self, result: SimulationResult) -> Dict[str, Any]:
        """格式化匹配引擎结果"""
        return {
            "final_action": result.final_action,
            "matched_rules_count": len(result.matched_rules),
            "chain_traversals": len(result.chain_traversal),
            "execution_path": result.execution_path,
            "matched_rules": [
                {
                    "rule_id": match_info.rule.rule_id,
                    "action": match_info.execution_action,
                    "match_result": match_info.match_result.value,
                    "matched_conditions": match_info.matched_conditions,
                    "unmatched_conditions": match_info.unmatched_conditions
                } for match_info in result.matched_rules
            ],
            "chain_details": [
                {
                    "table_name": chain_info.table_name,
                    "chain_name": chain_info.chain_name,
                    "final_action": chain_info.final_action,
                    "rules_processed": len(chain_info.rules_processed),
                    "default_policy": chain_info.default_policy
                } for chain_info in result.chain_traversal
            ],
            "metadata": result.metadata
        }
    
    def _process_with_table_processors(
        self, 
        ruleset: RuleSet, 
        traffic_request: TrafficRequest
    ) -> Dict[str, Any]:
        """使用表处理器进行分阶段处理"""
        table_results = {}
        
        # 确定流量方向对应的处理阶段
        direction_phase_map = {
            "inbound": ProcessingPhase.INPUT,
            "outbound": ProcessingPhase.OUTPUT,
            "forward": ProcessingPhase.FORWARD
        }
        
        # 默认使用INPUT阶段
        phase = direction_phase_map.get(
            getattr(traffic_request, 'direction', None), 
            ProcessingPhase.INPUT
        )
        
        # 按顺序处理每个表
        for table_name in self.table_order:
            if table_name in self.table_processors and table_name in ruleset.iptables_rules:
                processor = self.table_processors[table_name]
                table_rules = ruleset.iptables_rules[table_name]
                
                try:
                    result = processor.process_traffic(traffic_request, table_rules, phase)
                    
                    table_results[table_name] = {
                        "processor_class": processor.__class__.__name__,
                        "final_action": result.final_action,
                        "matched_rules": len(result.matched_rules),
                        "jump_results": len(result.jump_results),
                        "processing_phase": phase.value,
                        "details": {
                            "matched_rules": result.matched_rules,
                            "jump_results": result.jump_results
                        }
                    }
                    
                    logger.debug(f"{table_name}表处理完成: {result.final_action}")
                    
                except Exception as e:
                    logger.error(f"{table_name}表处理失败: {e}")
                    table_results[table_name] = {
                        "error": str(e),
                        "status": "failed"
                    }
        
        return table_results
    
    def _generate_recommendations(
        self, 
        matching_result: SimulationResult,
        ruleset: RuleSet,
        traffic_request: TrafficRequest
    ) -> List[Dict[str, Any]]:
        """生成建议"""
        recommendations = []
        
        # 性能建议
        if matching_result.metadata.get('statistics', {}).get('total_rules_checked', 0) > 100:
            recommendations.append({
                "type": "performance",
                "priority": "medium",
                "title": "规则数量较多",
                "description": f"检查了{matching_result.metadata['statistics']['total_rules_checked']}条规则，考虑优化规则顺序",
                "suggestion": "将常用规则放在前面，使用更具体的匹配条件"
            })
        
        # 安全建议
        if matching_result.final_action == "ACCEPT" and not matching_result.matched_rules:
            recommendations.append({
                "type": "security",
                "priority": "high", 
                "title": "默认允许策略",
                "description": "数据包未匹配任何规则但被允许通过",
                "suggestion": "检查默认策略设置，考虑使用更严格的规则"
            })
        
        # 规则建议
        if len(matching_result.matched_rules) > 5:
            recommendations.append({
                "type": "optimization",
                "priority": "low",
                "title": "匹配规则过多",
                "description": f"数据包匹配了{len(matching_result.matched_rules)}条规则",
                "suggestion": "考虑合并相似规则或调整规则顺序"
            })
        
        return recommendations
    
    def format_demo_output(
        self, 
        demo_result: Dict[str, Any], 
        output_format: str = "text",
        verbose: bool = False
    ) -> str:
        """格式化演示输出"""
        if output_format == "json":
            return json.dumps(demo_result, indent=2, ensure_ascii=False)
        
        # 文本格式输出
        output_lines = []
        
        # 标题
        output_lines.append("🔥 iptables流量演示结果")
        output_lines.append("=" * 60)
        
        # 流量信息
        req = demo_result["traffic_request"]
        output_lines.append("📊 流量信息:")
        output_lines.append(f"  源地址: {req['source_ip']}:{req.get('source_port', 'any')}")
        output_lines.append(f"  目标地址: {req['destination_ip']}:{req.get('destination_port', 'any')}")
        output_lines.append(f"  协议: {req['protocol']}")
        output_lines.append(f"  接口: {req.get('in_interface', 'any')} -> {req.get('out_interface', 'any')}")
        output_lines.append(f"  状态: {req.get('state', 'any')}")
        output_lines.append("")
        
        # 规则集信息
        ruleset_info = demo_result["ruleset_info"]
        output_lines.append("📋 规则集信息:")
        output_lines.append(f"  表数量: {ruleset_info['tables']}")
        output_lines.append(f"  规则总数: {ruleset_info['total_rules']}")
        output_lines.append("")
        
        # 最终决策
        final_decision = demo_result["final_decision"]
        decision_icon = "✅" if final_decision == "ACCEPT" else "❌" if final_decision == "DROP" else "⚠️"
        output_lines.append(f"🎯 最终决策: {decision_icon} {final_decision}")
        output_lines.append("")
        
        # 匹配引擎结果 - 只保留执行路径
        if "matching_engine_result" in demo_result:
            engine_result = demo_result["matching_engine_result"]
            
            # 详细执行路径
            output_lines.append("🔍 执行路径:")
            execution_path = engine_result.get('execution_path', [])
            self._format_execution_path(output_lines, execution_path)
            output_lines.append("")
        
        # 性能指标
        perf = demo_result["performance_metrics"]
        output_lines.append("⚡ 性能指标:")
        output_lines.append(f"  处理时间: {perf['total_time_ms']} ms")
        if "engine_stats" in perf:
            stats = perf["engine_stats"]
            output_lines.append(f"  检查规则数: {stats.get('total_rules_checked', 0)}")
            output_lines.append(f"  匹配成功数: {stats.get('total_matches', 0)}")
            output_lines.append(f"  平均规则/包: {stats.get('performance_metrics', {}).get('avg_rules_per_packet', 0):.1f}")
        output_lines.append("")
        
        
        return "\n".join(output_lines)
    
    def _format_execution_path(self, output_lines: list, execution_path: list) -> None:
        """格式化执行路径，使用rich库提供更清晰的可视化显示"""
        if not execution_path:
            output_lines.append("    (无执行路径)")
            return
        
        # 表颜色映射
        table_colors = {
            'raw': 'blue',
            'mangle': 'yellow', 
            'nat': 'green',
            'filter': 'red'
        }
        
        # 按表分组显示
        table_chains = {}  # 存储每个表的链信息
        
        # 首先按表分组
        for step in execution_path:
            if ' -> ' in step:
                chain_part, action_part = step.split(' -> ', 1)
                table_name, chain_name = chain_part.split('.', 1) if '.' in chain_part else (chain_part, '')
                
                if table_name not in table_chains:
                    table_chains[table_name] = []
                
                table_chains[table_name].append({
                    'chain_name': chain_name,
                    'action_part': action_part
                })
        
        # 按表顺序显示
        table_order = ['raw', 'mangle', 'nat', 'filter']
        for table_name in table_order:
            if table_name not in table_chains:
                continue
                
            # 创建表树
            table_color = table_colors.get(table_name, 'white')
            table_tree = Tree(f"[{table_color}]📋 {table_name.upper()}表[/{table_color}]")
            
            chains = table_chains[table_name]
            
            # 构建链的调用关系树
            chain_tree = self._build_chain_tree(chains)
            
            # 显示链树
            self._display_chain_tree_rich(table_tree, chain_tree)
            
            # 将树转换为文本并添加到输出
            with self.console.capture() as capture:
                self.console.print(table_tree)
            tree_text = capture.get()
            # 将多行文本分割并添加适当的缩进
            for line in tree_text.split('\n'):
                if line.strip():
                    output_lines.append(f"    {line}")
            
            # 表之间添加空行
            if table_name != table_order[-1]:
                output_lines.append("")
        
        # 添加总结
        output_lines.append("")
        output_lines.append("    📊 路径总结:")
        output_lines.append(f"      • 处理了 {len(table_chains)} 个表")
        output_lines.append(f"      • 遍历了 {len(execution_path)} 个链")
    
    def _build_chain_tree(self, chains: list) -> dict:
        """构建链的调用关系树"""
        # 找到主链（通常是OUTPUT、INPUT、FORWARD等）
        main_chains = ['OUTPUT', 'INPUT', 'FORWARD', 'PREROUTING', 'POSTROUTING']
        
        # 分离主链和子链
        main_chain = None
        sub_chains = []
        
        for chain_info in chains:
            if chain_info['chain_name'] in main_chains:
                main_chain = chain_info
            else:
                sub_chains.append(chain_info)
        
        # 如果没有找到主链，使用第一个链作为主链
        if not main_chain and chains:
            main_chain = chains[0]
            sub_chains = chains[1:]
        
        return {
            'main': main_chain,
            'subs': sub_chains
        }
    
    def _display_chain_tree_rich(self, tree: Tree, chain_tree: dict) -> None:
        """使用rich库显示链树"""
        main_chain = chain_tree.get('main')
        sub_chains = chain_tree.get('subs', [])
        
        if not main_chain:
            return
        
        # 显示主链
        chain_name = main_chain['chain_name']
        action_part = main_chain['action_part']
        
        # 确定动作图标和颜色
        if "ACCEPT" in action_part:
            action_icon = "✅"
            action_color = "green"
        elif "DROP" in action_part or "REJECT" in action_part:
            action_icon = "❌"
            action_color = "red"
        else:
            action_icon = "⚠️"
            action_color = "yellow"
        
        # 创建主链节点
        if "链不存在" in action_part:
            main_node = tree.add(f"[{action_color}]{action_icon} {chain_name} → RETURN (链不存在)[/{action_color}]")
        elif "匹配规则:" in action_part:
            action, rules_part = action_part.split(" (匹配规则:", 1)
            rules_part = rules_part.rstrip(")")
            
            main_node = tree.add(f"[{action_color}]{action_icon} {chain_name} → {action.strip()}[/{action_color}]")
            
            # 添加规则节点
            rules = rules_part.split("; ")
            for rule in rules:
                if rule.strip():
                    rule_icon = "📋" if "ID:" in rule else "🔧"
                    main_node.add(f"[dim]{rule_icon} {rule.strip()}[/dim]")
        elif "默认策略" in action_part:
            action = action_part.replace(" (默认策略)", "").strip()
            main_node = tree.add(f"[{action_color}]{action_icon} {chain_name} → {action} (默认策略)[/{action_color}]")
        else:
            main_node = tree.add(f"[{action_color}]{action_icon} {chain_name} → {action_part}[/{action_color}]")
        
        # 显示子链
        for sub_chain in sub_chains:
            sub_tree = {'main': sub_chain, 'subs': []}
            self._display_chain_tree_rich(main_node, sub_tree)
    
    def interactive_demo(self):
        """交互式演示"""
        print("🎮 iptables流量演示 - 交互模式")
        print("=" * 50)
        
        try:
            # 获取用户输入
            print("\n请输入流量参数:")
            source_ip = input("源IP地址 [192.168.1.100]: ").strip() or "192.168.1.100"
            destination_ip = input("目标IP地址 [10.0.0.1]: ").strip() or "10.0.0.1"
            protocol = input("协议 (tcp/udp/icmp) [tcp]: ").strip() or "tcp"
            
            traffic_params = {
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "protocol": protocol
            }
            
            if protocol in ["tcp", "udp"]:
                dst_port = input("目标端口 [80]: ").strip() or "80"
                traffic_params["destination_port"] = int(dst_port)
                
                src_port = input("源端口 [12345]: ").strip() or "12345"
                traffic_params["source_port"] = int(src_port)
            
            in_interface = input("入接口 [eth0]: ").strip() or "eth0"
            out_interface = input("出接口 [eth1]: ").strip() or "eth1"
            state = input("连接状态 [NEW]: ").strip() or "NEW"
            
            traffic_params.update({
                "in_interface": in_interface,
                "out_interface": out_interface,
                "state": state
            })
            
            # 执行演示
            print("\n🔄 正在分析流量...")
            demo_result = self.simulate_traffic(
                traffic_params=traffic_params,
                use_real_rules=True,
                detailed_output=True
            )
            
            # 显示结果
            print("\n" + self.format_demo_output(demo_result, "text", verbose=True))
            
        except KeyboardInterrupt:
            print("\n👋 演示已退出")
        except Exception as e:
            print(f"\n❌ 演示失败: {e}")
            logger.error(f"交互式演示失败: {e}")
    
