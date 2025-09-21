# -*- coding: utf-8 -*-
"""
CLI主入口
提供四大核心功能的命令行接口
"""

import typer
from typing import Optional, Literal
from pathlib import Path
import json
import sys
import os

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from src.infrastructure.logger import logger
from src.infrastructure.error_handler import IptablesAnalyzerError

app = typer.Typer(
    name="iptables-analyzer",
    help="Linux iptables/ipvs数据包流向分析工具",
    add_completion=False
)


@app.command()
def parse(
    output_file: Path = typer.Option("rules.json", "--output", "-o", help="输出JSON文件路径"),
    include_ipvs: bool = typer.Option(True, "--include-ipvs/--no-include-ipvs", help="是否包含ipvs规则"),
    table: Optional[str] = typer.Option(None, "--table", "-t", help="指定iptables表名")
):
    """解析iptables/ipvs规则并保存到JSON文件"""
    try:
        logger.info(f"开始解析规则，输出文件: {output_file}")
        
        # TODO: 实现规则解析逻辑
        # from src.services.parser_service import ParserService
        # parser = ParserService()
        # result = parser.parse_rules(include_ipvs=include_ipvs, table=table)
        
        # 临时实现：创建示例数据
        result = {
            "metadata": {
                "generated_at": "2024-01-15T10:30:00Z",
                "tool_version": "0.1.0",
                "environment": {
                    "os": "Linux",
                    "kernel_version": "6.1.0-39-amd64"
                }
            },
            "iptables_rules": {},
            "ipvs_rules": {"virtual_services": []}
        }
        
        # 保存结果到JSON文件
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        
        logger.info(f"规则已保存到: {output_file}")
        typer.echo(f"✅ 规则已保存到: {output_file}")
        
    except IptablesAnalyzerError as e:
        logger.error(f"解析失败: {e}")
        typer.echo(f"❌ 解析失败: {e}", err=True)
        raise typer.Exit(1)
    except Exception as e:
        logger.error(f"未知错误: {e}")
        typer.echo(f"❌ 未知错误: {e}", err=True)
        raise typer.Exit(1)


@app.command()
def demo(
    rules_file: Path = typer.Argument(..., help="规则JSON文件路径"),
    src_ip: str = typer.Argument(..., help="源IP地址"),
    dst_ip: str = typer.Argument(..., help="目标IP地址"),
    dst_port: int = typer.Argument(..., help="目标端口"),
    protocol: Literal["tcp", "udp", "icmp"] = typer.Argument(..., help="协议类型"),
    direction: Literal["inbound", "outbound", "forward"] = typer.Argument(..., help="流量方向"),
    output_format: Literal["text", "json"] = typer.Option("text", "--format", "-f", help="输出格式")
):
    """命令行演示流量匹配过程"""
    try:
        logger.info(f"开始流量演示: {src_ip} -> {dst_ip}:{dst_port} ({protocol}, {direction})")
        
        # 检查规则文件是否存在
        if not rules_file.exists():
            typer.echo(f"❌ 规则文件不存在: {rules_file}", err=True)
            raise typer.Exit(1)
        
        # 加载规则文件
        with open(rules_file, 'r', encoding='utf-8') as f:
            rules_data = json.load(f)
        
        # TODO: 实现流量演示逻辑
        # from src.demo.cli_demo import CLIDemo
        # cli_demo = CLIDemo()
        # result = cli_demo.simulate_traffic(rules_file, {
        #     "src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port,
        #     "protocol": protocol, "direction": direction
        # })
        
        # 临时实现：创建示例结果
        result = {
            "request": {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": protocol,
                "direction": direction
            },
            "table_results": [],
            "final_result": "ACCEPT"
        }
        
        # 格式化输出
        if output_format == "json":
            typer.echo(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            from src.utils.format_utils import FormatUtils
            formatted_result = FormatUtils.format_traffic_result(result, "text")
            typer.echo(formatted_result)
        
        logger.info("流量演示完成")
        
    except IptablesAnalyzerError as e:
        logger.error(f"演示失败: {e}")
        typer.echo(f"❌ 演示失败: {e}", err=True)
        raise typer.Exit(1)
    except Exception as e:
        logger.error(f"未知错误: {e}")
        typer.echo(f"❌ 未知错误: {e}", err=True)
        raise typer.Exit(1)


@app.command()
def process(
    rules_file: Path = typer.Argument(..., help="规则JSON文件路径"),
    matched_rules: str = typer.Argument(..., help="匹配到的规则ID列表，用逗号分隔"),
    action: Literal["k8s-service", "report"] = typer.Argument(..., help="处理动作")
):
    """处理匹配到的规则（如关联K8s服务）"""
    try:
        logger.info(f"开始处理规则: {matched_rules}, 动作: {action}")
        
        # 检查规则文件是否存在
        if not rules_file.exists():
            typer.echo(f"❌ 规则文件不存在: {rules_file}", err=True)
            raise typer.Exit(1)
        
        # 加载规则文件
        with open(rules_file, 'r', encoding='utf-8') as f:
            rules_data = json.load(f)
        
        # TODO: 实现规则处理逻辑
        # from src.services.processor_service import ProcessorService
        # processor = ProcessorService()
        # rule_ids = [rid.strip() for rid in matched_rules.split(',')]
        # result = processor.process_matched_rules(rule_ids, rules_data, action)
        
        # 临时实现：创建示例结果
        rule_ids = [rid.strip() for rid in matched_rules.split(',')]
        result = {
            "processed_rules": len(rule_ids),
            "action": action,
            "status": "success",
            "message": f"成功处理 {len(rule_ids)} 条规则"
        }
        
        typer.echo(f"✅ {result['message']}")
        logger.info(f"规则处理完成: {result}")
        
    except IptablesAnalyzerError as e:
        logger.error(f"处理失败: {e}")
        typer.echo(f"❌ 处理失败: {e}", err=True)
        raise typer.Exit(1)
    except Exception as e:
        logger.error(f"未知错误: {e}")
        typer.echo(f"❌ 未知错误: {e}", err=True)
        raise typer.Exit(1)


@app.command()
def version():
    """显示版本信息"""
    typer.echo("iptables-ipvs-analyzer v0.1.0")
    typer.echo("Linux iptables/ipvs数据包流向分析工具")


def main():
    """主函数"""
    try:
        app()
    except KeyboardInterrupt:
        typer.echo("\n👋 程序已退出")
        sys.exit(0)
    except Exception as e:
        logger.error(f"程序异常退出: {e}")
        typer.echo(f"❌ 程序异常退出: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
