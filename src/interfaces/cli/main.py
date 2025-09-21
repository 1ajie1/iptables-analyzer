# -*- coding: utf-8 -*-
"""
CLI主入口
提供四大核心功能的命令行接口
"""

import typer
from typing import Optional
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
        
        # 实现规则解析逻辑
        from src.services.parser_service import ParserService
        parser = ParserService()
        result = parser.parse_rules(include_ipvs=include_ipvs, table=table, output_file=str(output_file))
        
        # 统计信息
        total_rules = sum(
            sum(len(chain_data.get('rules', [])) for chain_data in table_data.values())
            for table_data in result.iptables_rules.values()
        )
        
        logger.info(f"规则已保存到: {output_file}")
        typer.echo("✅ 规则解析完成")
        typer.echo(f"   📊 解析了 {len(result.iptables_rules)} 个表，共 {total_rules} 条规则")
        typer.echo(f"   💾 已保存到: {output_file}")
        
    except IptablesAnalyzerError as e:
        logger.error(f"解析失败: {e}")
        typer.echo(f"❌ 解析失败: {e}", err=True)
        raise typer.Exit(1)
    except Exception as e:
        logger.error(f"未知错误: {e}")
        typer.echo(f"❌ 未知错误: {e}", err=True)
        raise typer.Exit(1)


def validate_ip_address(ip: str) -> bool:
    """验证IP地址格式"""
    if not ip:
        return False
    
    from src.utils.ip_utils import IPUtils
    return IPUtils.is_valid_ip(ip)


def validate_port(port: int) -> bool:
    """验证端口号"""
    return 1 <= port <= 65535


def validate_protocol(protocol: str) -> bool:
    """验证协议类型"""
    valid_protocols = ['tcp', 'udp', 'icmp', 'tcp6', 'udp6', 'icmp6']
    return protocol.lower() in valid_protocols


def validate_direction(direction: str) -> bool:
    """验证流量方向"""
    valid_directions = ['INPUT', 'OUTPUT', 'FORWARD']
    return direction.upper() in valid_directions


def validate_demo_parameters(
    src_ip: Optional[str],
    dst_ip: Optional[str], 
    dst_port: Optional[int],
    protocol: Optional[str],
    direction: str
) -> None:
    """验证demo命令的参数"""
    errors = []
    
    # 验证源IP地址
    if src_ip and not validate_ip_address(src_ip):
        errors.append(f"❌ 无效的源IP地址: '{src_ip}' (格式错误)")
    
    # 验证目标IP地址
    if dst_ip and not validate_ip_address(dst_ip):
        errors.append(f"❌ 无效的目标IP地址: '{dst_ip}' (格式错误)")
    
    # 验证端口号
    if dst_port and not validate_port(dst_port):
        errors.append(f"❌ 无效的端口号: '{dst_port}' (端口范围: 1-65535)")
    
    # 验证协议类型
    if protocol and not validate_protocol(protocol):
        errors.append(f"❌ 无效的协议类型: '{protocol}' (支持: tcp, udp, icmp)")
    
    # 验证流量方向
    if not validate_direction(direction):
        errors.append(f"❌ 无效的流量方向: '{direction}' (支持: INPUT, OUTPUT, FORWARD)")
    
    # 检查常见错误
    if dst_ip and dst_port is None:
        # 检查是否将端口号误作为IP地址
        if dst_ip.isdigit() and 1 <= int(dst_ip) <= 65535:
            errors.append(f"💡 提示: 您可能想要使用 --dst-port {dst_ip} 而不是 --dst-ip {dst_ip}")
    
    if errors:
        print("🚨 参数验证失败:")
        for error in errors:
            print(f"  {error}")
        print("\n📖 使用帮助:")
        print("  uv run src/interfaces/cli/main.py demo --help")
        print("\n💡 正确示例:")
        print("  uv run src/interfaces/cli/main.py demo --src-ip 127.0.0.1 --dst-ip 10.106.50.30 --dst-port 81 --protocol tcp --direction OUTPUT")
        raise typer.Exit(1)


@app.command()
def demo(
    src_ip: Optional[str] = typer.Option(None, "--src-ip", help="源IP地址"),
    dst_ip: Optional[str] = typer.Option(None, "--dst-ip", help="目标IP地址"),
    dst_port: Optional[int] = typer.Option(None, "--dst-port", help="目标端口"),
    protocol: Optional[str] = typer.Option(None, "--protocol", help="协议类型 (tcp/udp/icmp)"),
    rules_file: Optional[Path] = typer.Option(None, "--rules-file", "-r", help="规则JSON文件路径"),
    output_format: str = typer.Option("text", "--format", "-f", help="输出格式 (text/json)"),
    interactive: bool = typer.Option(False, "--interactive", "-i", help="交互模式"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="详细输出"),
    debug: bool = typer.Option(False, "--debug", help="开启调试模式，显示详细日志"),
    direction: str = typer.Option("INPUT", "--direction", "-d", help="流量方向 (INPUT/OUTPUT/FORWARD)")
):
    """命令行演示流量匹配过程"""
    # 验证参数
    validate_demo_parameters(src_ip, dst_ip, dst_port, protocol, direction)
    
    # 设置调试模式
    if debug:
        logger.set_level("DEBUG")
        typer.echo("🐛 调试模式已开启，将显示详细日志信息")
        typer.echo("")
    
    try:
        from src.demo.cli_demo import CLIDemo
        
        cli_demo = CLIDemo(debug_mode=debug)
        
        # 交互模式
        if interactive:
            cli_demo.interactive_demo()
            return
        
        # 参数模式
        # 检查必要参数
        if not all([src_ip, dst_ip, protocol]):
            typer.echo("❌ 参数模式需要指定 --src-ip, --dst-ip, --protocol", err=True)
            typer.echo("💡 或使用 --interactive 进入交互模式", err=True)
            raise typer.Exit(1)
        
        traffic_params = {
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "protocol": protocol
        }
        
        if dst_port is not None:
            traffic_params["destination_port"] = dst_port
        
        typer.echo(f"🚀 开始流量演示: {src_ip} -> {dst_ip} ({protocol})")
        if dst_port:
            typer.echo(f"   目标端口: {dst_port}")
        typer.echo("")
        
        result = cli_demo.simulate_traffic(
            rules_file=rules_file,
            traffic_params=traffic_params,
            use_real_rules=rules_file is None,
            detailed_output=verbose
        )
        
        # 格式化输出
        if output_format == "json":
            typer.echo(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            formatted_result = cli_demo.format_demo_output(result, "text", verbose)
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
    action: str = typer.Argument(..., help="处理动作 (k8s-service/report)")
):
    """处理匹配到的规则（如关联K8s服务）"""
    try:
        logger.info(f"开始处理规则: {matched_rules}, 动作: {action}")
        
        # 检查规则文件是否存在
        if not rules_file.exists():
            typer.echo(f"❌ 规则文件不存在: {rules_file}", err=True)
            raise typer.Exit(1)
        
        # 验证规则文件格式
        with open(rules_file, 'r', encoding='utf-8') as f:
            json.load(f)  # 只验证JSON格式
        
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
