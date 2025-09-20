# iptables/ipvs 数据包流向分析工具架构设计

## 架构概述

### 四大核心功能
本工具提供四大核心功能，每个功能都有明确的职责和输出：

1. **规则解析功能 (parse)**：从Linux系统获取iptables/ipvs规则，生成结构化JSON文件
2. **命令行演示功能 (demo)**：使用指定参数演示流量匹配过程，直接输出结果
3. **Web演示功能 (web_demo)**：基于JSON文件生成交互式静态网页，用户可自由设置参数
4. **规则处理功能 (process)**：对匹配到的规则进行后续处理，当前支持K8s服务关联

### 设计原则
- **单文件工具**：所有功能集成在一个可执行文件中
- **模块化设计**：各模块职责单一，低耦合高内聚
- **易维护性**：代码结构清晰，便于个人开发和维护
- **性能优先**：针对个人开发场景优化，避免过度设计
- **简化部署**：无需复杂配置，直接运行

### 整体架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                    iptables/ipvs 数据包流向分析工具                    │
├─────────────────────────────────────────────────────────────────┤
│  用户接口层 (User Interface Layer)                               │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐   │
│  │   parse 命令     │  │   demo 命令      │  │  web_demo 命令   │   │
│  │  (规则解析)      │  │  (CLI演示)       │  │  (Web演示)       │   │
│  │ 生成JSON文件     │  │ 命令行参数演示   │  │ 生成交互式网页   │   │
│  │ 支持多数据源     │  │ 直接输出结果     │  │ 支持文件上传     │   │
│  │ 多数据源切换     │   │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘   │
│  ┌─────────────────┐                                            │
│  │  process 命令    │                                            │
│  │  (规则处理)      │                                            │
│  │ K8s服务关联     │                                            │
│  │ 后续扩展功能     │                                            │
│  └─────────────────┘                                            │
├─────────────────────────────────────────────────────────────────┤
│  核心功能层 (Core Functions Layer)                               │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐   │
│  │   规则解析模块    │  │   流量演示模块    │  │   规则处理模块    │   │
│  │  (Parser)       │  │  (Demo)         │  │  (Processor)    │   │
│  │ 整合多数据源     │  │ 匹配算法演示     │  │ 结果后处理       │   │
│  │ 规则标准化       │  │ 可视化展示       │  │ 服务关联         │   │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘   │
├─────────────────────────────────────────────────────────────────┤
│  数据访问层 (Data Access Layer)                                  │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐   │
│  │  iptables 解析   │  │   ipvs 解析     │  │  K8s 客户端     │   │
│  │  (IptablesDAO)  │  │  (IpvsDAO)      │  │  (K8sClient)    │   │
│  │ 防火墙规则解析   │  │ 负载均衡规则     │  │ 容器编排信息     │   │
│  │ 支持4个表        │  │ XML格式解析     │  │ Service/Endpoint│   │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘   │
├─────────────────────────────────────────────────────────────────┤
│  基础设施层 (Infrastructure Layer)                               │
│  ┌─────────────────┐  ┌─────────────────┐                       │
│  │   配置管理       │  │   日志服务       │                       │
│  │  (Config)       │  │  (Logger)       │                       │
│  │ YAML配置解析     │  │ 分级日志输出     │                       │
│  │ 环境变量支持     │  │ 文件/控制台     │                       │
│  └─────────────────┘  └─────────────────┘                       │
├─────────────────────────────────────────────────────────────────┤
│  系统层 (System Layer)                                          │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐   │
│  │  Linux 内核     │  │   Kubernetes    │  │   文件系统       │   │
│  │  (iptables/ipvs)│  │   (API Server)  │  │  (报告输出)      │   │
│  │ 内核网络栈      │  │ 容器编排平台     │  │ 本地文件存储     │   │
│  │ 规则存储执行     │  │ 服务发现        │  │ 报告文件生成     │   │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 详细模块设计

### 1. 用户接口层 (User Interface Layer)

#### 1.1 CLI接口模块
```python
# src/interfaces/cli/main.py
# 功能：提供三大核心功能的命令行接口
# 特点：使用Typer框架，支持自动帮助生成和参数验证
import typer
from typing import Optional, Literal
from pathlib import Path

app = typer.Typer(
    name="iptables-analyzer",
    help="Linux iptables/ipvs数据包流向分析工具"
)

@app.command()
def parse(
    output_file: Path = typer.Option("rules.json", "--output", "-o"),
    include_ipvs: bool = typer.Option(True, "--include-ipvs/--no-include-ipvs"),
    table: Optional[str] = typer.Option(None, "--table", "-t")
):
    """解析iptables/ipvs规则并保存到JSON文件
    功能：从系统获取防火墙和负载均衡规则，转换为标准JSON格式
    参数：output_file-输出文件路径，include_ipvs-是否包含ipvs规则，table-指定iptables表
    """
    from src.services.parser_service import ParserService
    import json
    
    parser = ParserService()
    result = parser.parse_rules(include_ipvs=include_ipvs, table=table)
    
    # 保存结果到JSON文件
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
    
    typer.echo(f"规则已保存到: {output_file}")

@app.command()
def demo(
    rules_file: Path = typer.Argument(..., help="规则JSON文件路径"),
    src_ip: str = typer.Argument(..., help="源IP地址"),
    dst_ip: str = typer.Argument(..., help="目标IP地址"),
    dst_port: int = typer.Argument(..., help="目标端口"),
    protocol: Literal["tcp", "udp", "icmp"] = typer.Argument(..., help="协议"),
    direction: Literal["inbound", "outbound", "forward"] = typer.Argument(..., help="流量方向"),
    output_format: Literal["text", "json"] = typer.Option("text", "--format", "-f")
):
    """命令行演示流量匹配过程
    功能：使用指定参数演示数据包通过iptables/ipvs规则的匹配过程
    参数：rules_file-规则文件，src_ip/dst_ip-源/目标IP，dst_port-目标端口，protocol-协议类型，direction-流量方向
    """
    from src.demo.cli_demo import CLIDemo
    import json
    
    # 命令行演示 - 使用传入的参数
    traffic_params = {
        "src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port,
        "protocol": protocol, "direction": direction
    }
    
    cli_demo = CLIDemo()
    result = cli_demo.simulate_traffic(rules_file, traffic_params)
    
    # 格式化输出
    if output_format == "json":
        typer.echo(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        typer.echo(f"流量演示结果: {result.final_result}")
        for table_result in result.table_results:
            typer.echo(f"表 {table_result.table_name}: {table_result.final_action}")

@app.command()
def web_demo(
    output_file: Path = typer.Option("./demo.html", "--output", "-o", help="输出HTML文件路径"),
    default_rules: Path = typer.Option(None, "--default-rules", help="默认规则JSON文件路径（可选）")
):
    """生成Web交互式演示页面
    功能：生成支持文件上传的交互式静态网页，用户可上传JSON文件作为数据源并设置参数查看匹配结果
    参数：output_file-输出HTML文件路径，default_rules-默认规则文件（可选）
    """
    from src.demo.web_demo.web_generator import WebDemoGenerator
    
    # Web演示 - 生成支持文件上传的交互式静态网页
    web_generator = WebDemoGenerator()
    web_path = web_generator.generate_demo_page(str(output_file), default_rules)
    typer.echo(f"Web演示页面已生成: {web_path}")
    typer.echo("请在浏览器中打开该文件，可以上传JSON文件作为数据源并交互式地设置参数查看匹配结果")

@app.command()
def process(
    rules_file: Path = typer.Argument(..., help="规则JSON文件路径"),
    matched_rules: str = typer.Argument(..., help="匹配到的规则ID列表，用逗号分隔"),
    action: Literal["k8s-service", "report"] = typer.Argument(..., help="处理动作")
):
    """处理匹配到的规则（如关联K8s服务）
    功能：根据匹配结果进行后续处理，当前支持K8s服务关联
    参数：rules_file-规则文件，matched_rules-匹配的规则ID，action-处理动作
    """
    from src.services.processor_service import ProcessorService
    import json
    
    # 加载规则文件
    with open(rules_file, 'r', encoding='utf-8') as f:
        rules_data = json.load(f)
    
    processor = ProcessorService()
    rule_ids = [rid.strip() for rid in matched_rules.split(',')]
    result = processor.process_matched_rules(rule_ids, rules_data, action)
    
    typer.echo(f"处理完成: {result}")

if __name__ == "__main__":
    app()
```


### 2. 核心功能层 (Core Functions Layer)

#### 2.1 规则解析模块 (Parser Module)
```python
# src/services/parser_service.py
# 功能：整合多个数据源，提供统一的规则解析接口
# 特点：支持iptables/ipvs/K8s数据源，规则标准化，K8s资源关联
from typing import Dict, List, Optional
from src.data_access.iptables_dao import IptablesDAO
from src.data_access.ipvs_dao import IpvsDAO
from src.data_access.k8s_client import K8sClient
from src.models.rule_models import RuleSet, IptablesRule, IpvsRule

class ParserService:
    def __init__(self):
        self.iptables_dao = IptablesDAO()
        self.ipvs_dao = IpvsDAO()
        self.k8s_client = K8sClient()
    
    def parse_rules(
        self, 
        include_ipvs: bool = True, 
        table: Optional[str] = None
    ) -> RuleSet:
        """解析所有规则
        功能：从系统获取iptables/ipvs规则，关联K8s资源，返回标准化规则集
        参数：include_ipvs-是否包含ipvs规则，table-指定iptables表名
        返回：RuleSet对象，包含所有解析后的规则
        """
        ruleset = RuleSet()
        
        # 解析iptables规则
        iptables_rules = self.iptables_dao.get_rules(table=table)
        ruleset.iptables_rules = iptables_rules
        
        # 解析ipvs规则
        if include_ipvs:
            ipvs_rules = self.ipvs_dao.get_rules()
            ruleset.ipvs_rules = ipvs_rules
        
        # 关联K8s资源
        if self.k8s_client.is_available():
            self._associate_k8s_resources(ruleset)
        
        return ruleset
    
    def _associate_k8s_resources(self, ruleset: RuleSet):
        """关联Kubernetes资源"""
        services = self.k8s_client.get_services()
        endpoints = self.k8s_client.get_endpoints()
        
        for rule in ruleset.iptables_rules:
            if rule.chain_name.startswith('KUBE-SVC-'):
                # 关联Service资源
                rule.k8s_resource = self._find_k8s_service(rule, services)
            elif rule.chain_name.startswith('KUBE-SEP-'):
                # 关联Endpoint资源
                rule.k8s_resource = self._find_k8s_endpoint(rule, endpoints)
```

#### 2.2 流量演示模块 (Demo Module)
```python
# src/demo/cli_demo.py
# 功能：命令行演示流量匹配过程
# 特点：支持文本和JSON格式输出，清晰的匹配路径展示
from typing import Dict, List
from src.models.traffic_models import TrafficRequest, SimulationResult
from src.models.rule_models import RuleSet
from src.core.matching_engine import MatchingEngine
from src.core.table_processor import TableProcessor

class CLIDemo:
    def __init__(self):
        self.matching_engine = MatchingEngine()
        self.table_processor = TableProcessor()
    
    def simulate_traffic(self, rules_file: str, traffic_params: Dict) -> SimulationResult:
        """命令行演示流量匹配
        功能：演示数据包通过iptables规则的匹配过程，按表优先级处理
        参数：rules_file-规则JSON文件路径，traffic_params-流量参数
        返回：SimulationResult对象，包含匹配结果和最终动作
        """
        import json
        
        # 加载规则文件
        with open(rules_file, 'r', encoding='utf-8') as f:
            rules_data = json.load(f)
        
        # 从JSON数据构建规则集
        ruleset = self._build_ruleset_from_json(rules_data)
        
        # 创建流量请求
        request = TrafficRequest(**traffic_params)
        
        # 按表优先级处理
        result = SimulationResult(request=request)
        
        for table_name in ['raw', 'mangle', 'nat', 'filter']:
            table_result = self.table_processor.process_table(
                table_name, request, ruleset
            )
            result.add_table_result(table_result)
            
            # 如果流量被拒绝，停止处理
            if table_result.final_action in ['DROP', 'REJECT']:
                break
        
        return result

# src/demo/web_demo/web_generator.py
# 功能：生成支持文件上传的交互式静态Web演示页面
# 特点：支持JSON文件上传作为数据源，支持多数据源切换，无需服务器
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

class WebDemoGenerator:
    def __init__(self):
        self.template_env = Environment(loader=FileSystemLoader('src/demo/web_demo/templates'))
    
    def generate_demo_page(self, output_path: str, default_rules_file: str = None) -> str:
        """生成支持文件上传的交互式Web演示页面
        功能：生成支持JSON文件上传的静态HTML页面，用户可上传规则文件并设置参数查看匹配结果
        特点：支持多数据源切换，用户可在网页上上传JSON文件、设置IP、端口、协议等参数
        参数：output_path-输出文件路径，default_rules_file-默认规则文件（可选）
        返回：生成的文件路径
        """
        import json
        
        # 准备默认规则数据（如果提供）
        default_rules_data = None
        if default_rules_file and Path(default_rules_file).exists():
            with open(default_rules_file, 'r', encoding='utf-8') as f:
                default_rules_data = json.load(f)
        
        # 渲染模板，嵌入默认规则数据和JavaScript匹配逻辑
        template = self.template_env.get_template('web-demo.html')
        html_content = template.render(
            default_rules_data=json.dumps(default_rules_data, ensure_ascii=False) if default_rules_data else None,
            tool_name="iptables-ipvs-analyzer",
            version="1.0.0"
        )
        
        # 保存文件
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_path
```

#### Web演示页面功能说明
生成的静态HTML页面包含以下交互功能：

**数据源管理区域**：
- JSON文件上传功能（支持拖拽上传）
- 数据源切换下拉框（支持多个已上传的文件）
- 当前数据源显示和验证状态
- 数据源信息展示（规则数量、表类型等）

**参数设置区域**：
- 源IP地址输入框（支持IP段，如192.168.1.0/24）
- 源端口输入框（支持单个端口或范围，如80-8080）
- 目标IP地址输入框
- 目标端口输入框
- 协议下拉选择（tcp/udp/icmp）
- 流量方向下拉选择（inbound/outbound/forward）
- "查询匹配规则"按钮

**结果显示区域**：
- 匹配路径展示（按表顺序显示经过的规则）
- 命中规则详情（规则ID、匹配条件、动作、K8s资源关联）
- 最终处理结果（允许/拒绝/转发）
- 结果过滤和搜索功能

**技术特点**：
- 纯静态HTML+JavaScript，无需服务器
- 支持动态文件上传和JSON解析
- 支持多数据源切换和管理
- 前端匹配算法与后端保持一致
- 支持实时参数修改和结果更新

#### 2.3 规则处理模块 (Processor Module)
```python
# src/services/processor_service.py
# 功能：处理匹配到的规则，进行后续分析
# 特点：当前支持K8s服务关联，未来可扩展其他处理逻辑
from typing import Dict, List, Optional
from src.data_access.k8s_client import K8sClient

class ProcessorService:
    def __init__(self):
        self.k8s_client = K8sClient()
    
    def process_matched_rules(
        self, 
        rule_ids: List[str], 
        rules_data: Dict, 
        action: str
    ) -> Dict:
        """处理匹配到的规则
        功能：根据匹配结果进行后续处理，当前支持K8s服务关联
        参数：rule_ids-匹配的规则ID列表，rules_data-规则数据，action-处理动作
        返回：处理结果字典
        """
        if action == "k8s-service":
            return self._associate_k8s_services(rule_ids, rules_data)
        elif action == "report":
            return self._generate_processing_report(rule_ids, rules_data)
        else:
            return {"error": f"不支持的处理动作: {action}"}
    
    def _associate_k8s_services(self, rule_ids: List[str], rules_data: Dict) -> Dict:
        """关联K8s服务
        功能：将匹配的规则与K8s服务进行关联
        参数：rule_ids-规则ID列表，rules_data-规则数据
        返回：关联结果
        """
        if not self.k8s_client.is_available():
            return {"error": "K8s客户端不可用"}
        
        # 获取K8s资源
        services = self.k8s_client.get_services()
        endpoints = self.k8s_client.get_endpoints()
        
        associations = []
        for rule_id in rule_ids:
            # 查找规则
            rule = self._find_rule_by_id(rule_id, rules_data)
            if not rule:
                continue
            
            # 关联K8s服务
            k8s_info = self._find_k8s_association(rule, services, endpoints)
            if k8s_info:
                associations.append({
                    "rule_id": rule_id,
                    "k8s_resource": k8s_info
                })
        
        return {
            "total_rules": len(rule_ids),
            "associated_rules": len(associations),
            "associations": associations
        }
    
    def _generate_processing_report(self, rule_ids: List[str], rules_data: Dict) -> Dict:
        """生成处理报告
        功能：生成规则处理的分析报告
        参数：rule_ids-规则ID列表，rules_data-规则数据
        返回：报告数据
        """
        # 实现报告生成逻辑
        return {
            "processed_rules": len(rule_ids),
            "report_type": "processing_analysis",
            "timestamp": "2024-01-01T00:00:00Z"
        }
```

### 3. 数据访问层 (Data Access Layer)

#### 3.1 iptables数据访问对象
```python
# src/data_access/iptables_dao.py
# 功能：从Linux系统获取iptables规则，解析为标准格式
# 特点：使用python-iptables库，支持4个表，错误处理，规则标准化
import iptc
from typing import List, Optional, Dict
from src.models.rule_models import IptablesRule, RuleTable

class IptablesDAO:
    def __init__(self):
        self.tables = ['filter', 'nat', 'mangle', 'raw']
    
    def get_rules(self, table: Optional[str] = None) -> List[IptablesRule]:
        """获取iptables规则
        功能：从系统获取iptables规则，支持指定表或全部表
        参数：table-指定表名(filter/nat/mangle/raw)，None表示获取所有表
        返回：IptablesRule对象列表，包含解析后的规则信息
        """
        rules = []
        tables_to_process = [table] if table else self.tables
        
        for table_name in tables_to_process:
            try:
                table_rules = self._parse_table(table_name)
                rules.extend(table_rules)
            except Exception as e:
                # 记录错误，继续处理其他表
                self._log_error(f"Failed to parse table {table_name}: {e}")
        
        return rules
    
    def _parse_table(self, table_name: str) -> List[IptablesRule]:
        """解析指定表的规则"""
        rules = []
        table = iptc.Table(iptc.Table.__dict__[table_name.upper()])
        
        for chain in table.chains:
            for rule in chain.rules:
                parsed_rule = self._parse_rule(rule, table_name, chain.name)
                rules.append(parsed_rule)
        
        return rules
    
    def _parse_rule(self, rule, table_name: str, chain_name: str) -> IptablesRule:
        """解析单个规则"""
        return IptablesRule(
            table=table_name,
            chain=chain_name,
            source_ip=self._extract_source_ip(rule),
            destination_ip=self._extract_destination_ip(rule),
            protocol=self._extract_protocol(rule),
            source_port=self._extract_source_port(rule),
            destination_port=self._extract_destination_port(rule),
            action=self._extract_action(rule),
            jump_chain=self._extract_jump_chain(rule)
        )
```

#### 3.2 ipvs数据访问对象
```python
# src/data_access/ipvs_dao.py
# 功能：从Linux系统获取ipvs负载均衡规则，解析虚拟服务和真实服务器
# 特点：使用ipvsadm命令，XML格式解析，支持多种调度算法
import subprocess
import xml.etree.ElementTree as ET
from typing import List, Dict
from src.models.rule_models import IpvsRule, VirtualService, RealServer

class IpvsDAO:
    def get_rules(self) -> List[IpvsRule]:
        """获取ipvs规则
        功能：从系统获取ipvs负载均衡规则，解析虚拟服务和真实服务器信息
        返回：IpvsRule对象列表，包含虚拟服务和真实服务器配置
        """
        try:
            # 使用ipvsadm命令获取XML格式输出
            result = subprocess.run(
                ['ipvsadm', '-L', '-n', '--xml'],
                capture_output=True, text=True, check=True
            )
            return self._parse_xml_output(result.stdout)
        except subprocess.CalledProcessError as e:
            self._log_error(f"Failed to get ipvs rules: {e}")
            return []
    
    def _parse_xml_output(self, xml_content: str) -> List[IpvsRule]:
        """解析XML输出"""
        root = ET.fromstring(xml_content)
        rules = []
        
        for vs_elem in root.findall('virtualserver'):
            vs = VirtualService(
                ip=vs_elem.get('address'),
                port=vs_elem.get('port'),
                protocol=vs_elem.get('protocol'),
                scheduler=vs_elem.get('scheduler')
            )
            
            real_servers = []
            for rs_elem in vs_elem.findall('realserver'):
                rs = RealServer(
                    ip=rs_elem.get('address'),
                    port=rs_elem.get('port'),
                    weight=rs_elem.get('weight')
                )
                real_servers.append(rs)
            
            rule = IpvsRule(
                virtual_service=vs,
                real_servers=real_servers
            )
            rules.append(rule)
        
        return rules
```

### 4. 核心算法层 (Core Algorithms)

#### 4.1 匹配引擎
```python
# src/core/matching_engine.py
# 功能：实现iptables规则的匹配算法，支持IP、端口、协议匹配
# 特点：使用ipaddress库进行网段匹配，支持CIDR表示法，高效匹配算法
import ipaddress
from typing import List, Optional
from src.models.rule_models import IptablesRule
from src.models.traffic_models import TrafficRequest

class MatchingEngine:
    def match_rule(self, rule: IptablesRule, request: TrafficRequest) -> bool:
        """匹配单个规则
        功能：检查流量请求是否匹配指定的iptables规则
        参数：rule-iptables规则对象，request-流量请求对象
        返回：True表示匹配，False表示不匹配
        """
        # IP匹配
        if not self._match_ip(rule, request):
            return False
        
        # 端口匹配
        if not self._match_port(rule, request):
            return False
        
        # 协议匹配
        if not self._match_protocol(rule, request):
            return False
        
        return True
    
    def _match_ip(self, rule: IptablesRule, request: TrafficRequest) -> bool:
        """IP地址匹配"""
        # 源IP匹配
        if rule.source_ip and not self._ip_in_network(request.src_ip, rule.source_ip):
            return False
        
        # 目标IP匹配
        if rule.destination_ip and not self._ip_in_network(request.dst_ip, rule.destination_ip):
            return False
        
        return True
    
    def _ip_in_network(self, ip: str, network: str) -> bool:
        """检查IP是否在网段内"""
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(network)
        except ValueError:
            return False
```

#### 4.2 表处理器
```python
# src/core/table_processor.py
# 功能：按iptables表优先级处理规则，实现跳转链处理
# 特点：支持4个表的优先级处理，跳转链递归处理，链名映射
from typing import List
from src.models.traffic_models import TrafficRequest, TableResult
from src.models.rule_models import RuleSet
from src.core.matching_engine import MatchingEngine

class TableProcessor:
    def __init__(self):
        self.matching_engine = MatchingEngine()
    
    def process_table(
        self, 
        table_name: str, 
        request: TrafficRequest, 
        ruleset: RuleSet
    ) -> TableResult:
        """处理指定表的规则
        功能：处理指定iptables表的规则，按链顺序匹配，支持跳转链
        参数：table_name-表名，request-流量请求，ruleset-规则集
        返回：TableResult对象，包含匹配结果和最终动作
        """
        result = TableResult(table_name=table_name)
        
        # 获取对应链的规则
        chain_name = self._get_chain_name(request.direction)
        rules = self._get_chain_rules(ruleset, table_name, chain_name)
        
        # 按顺序匹配规则
        for rule in rules:
            if self.matching_engine.match_rule(rule, request):
                result.matched_rules.append(rule)
                result.final_action = rule.action
                
                # 如果是跳转链，处理跳转
                if rule.jump_chain:
                    jump_result = self._process_jump_chain(
                        rule.jump_chain, request, ruleset
                    )
                    result.jump_results.append(jump_result)
                
                break
        
        return result
```

### 5. 数据模型层 (Data Models)

#### 5.1 规则模型
```python
# src/models/rule_models.py
# 功能：定义iptables和ipvs规则的数据结构
# 特点：使用dataclass简化代码，支持JSON序列化，包含K8s资源关联
from dataclasses import dataclass
from typing import List, Optional, Dict, Any

@dataclass
class IptablesRule:
    table: str
    chain: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    protocol: Optional[str] = None
    source_port: Optional[str] = None
    destination_port: Optional[str] = None
    action: str = "ACCEPT"
    jump_chain: Optional[str] = None
    k8s_resource: Optional[Dict[str, Any]] = None

@dataclass
class VirtualService:
    ip: str
    port: str
    protocol: str
    scheduler: str

@dataclass
class RealServer:
    ip: str
    port: str
    weight: str

@dataclass
class IpvsRule:
    virtual_service: VirtualService
    real_servers: List[RealServer]

@dataclass
class RuleSet:
    iptables_rules: List[IptablesRule] = None
    ipvs_rules: List[IpvsRule] = None
    
    def to_dict(self) -> dict:
        """转换为字典格式，便于JSON序列化"""
        return {
            'iptables_rules': [rule.__dict__ for rule in (self.iptables_rules or [])],
            'ipvs_rules': [rule.__dict__ for rule in (self.ipvs_rules or [])]
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'RuleSet':
        """从字典创建RuleSet对象"""
        iptables_rules = [IptablesRule(**rule) for rule in data.get('iptables_rules', [])]
        ipvs_rules = [IpvsRule(**rule) for rule in data.get('ipvs_rules', [])]
        return cls(iptables_rules=iptables_rules, ipvs_rules=ipvs_rules)
```

#### 5.2 流量模型
```python
# src/models/traffic_models.py
# 功能：定义流量请求和模拟结果的数据结构
# 特点：支持多种协议和方向，包含匹配结果和最终动作
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class TrafficRequest:
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    direction: str
    src_port: Optional[int] = None

@dataclass
class TableResult:
    table_name: str
    matched_rules: List = None
    final_action: str = "ACCEPT"
    jump_results: List = None

@dataclass
class SimulationResult:
    request: TrafficRequest
    table_results: List[TableResult] = None
    final_result: str = "ACCEPT"
    
    def to_dict(self) -> dict:
        """转换为字典格式，便于JSON序列化"""
        return {
            'request': self.request.__dict__,
            'table_results': [result.__dict__ for result in (self.table_results or [])],
            'final_result': self.final_result
        }
```

### 6. 基础设施层 (Infrastructure Layer)

#### 6.1 配置管理
```python
# src/infrastructure/config.py
# 功能：管理应用程序配置，支持YAML文件和环境变量
# 特点：提供默认配置，支持配置热加载，类型安全
import yaml
from pathlib import Path
from typing import Dict, Any

class Config:
    def __init__(self, config_file: str = "config.yaml"):
        self.config_file = Path(config_file)
        self._config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """加载配置文件"""
        if self.config_file.exists():
            with open(self.config_file, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """获取默认配置"""
        return {
            'parser': {
                'iptables': {
                    'enabled': True
                },
                'ipvs': {
                    'enabled': True
                }
            },
            'simulator': {
                'performance': {
                    'max_workers': 4
                }
            },
            'visualization': {
                'charts': {
                    'max_rules_display': 1000
                }
            }
        }
```

#### 6.2 日志服务
```python
# src/infrastructure/logger.py
# 功能：提供分级日志服务，支持文件和控制台输出
# 特点：支持DEBUG/INFO/WARNING/ERROR级别，可配置输出目标
import logging
from pathlib import Path
from typing import Optional

class Logger:
    def __init__(self, log_file: Optional[str] = None):
        self.logger = logging.getLogger('iptables-analyzer')
        self.logger.setLevel(logging.INFO)
        
        # 控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # 文件处理器（可选）
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            self.logger.addHandler(file_handler)
        
        self.logger.addHandler(console_handler)
    
    def info(self, message: str):
        """记录信息日志"""
        self.logger.info(message)
    
    def error(self, message: str):
        """记录错误日志"""
        self.logger.error(message)
    
    def debug(self, message: str):
        """记录调试日志"""
        self.logger.debug(message)
```

---

## 项目目录结构

### 开发阶段（模块化结构）
```
iptables-ipvs-analyzer/
├── src/
│   ├── interfaces/          # 用户接口层
│   │   └── cli/
│   │       └── main.py      # CLI主入口，提供parse/demo/process三大命令
│   ├── services/            # 核心功能层
│   │   ├── parser_service.py    # 规则解析服务，整合iptables/ipvs/K8s数据源
│   │   └── processor_service.py # 规则处理服务，处理匹配结果（K8s关联等）
│   ├── demo/                # 流量演示模块
│   │   ├── cli_demo.py          # 命令行演示，支持文本/JSON格式输出
│   │   └── web_demo/            # Web演示（交互式静态网页）
│   │       ├── static/          # 静态资源
│   │       │   ├── css/
│   │       │   │   └── style.css          # 网页样式，支持响应式设计
│   │       │   └── js/
│   │       │       ├── rule-matcher.js    # 前端规则匹配逻辑（与后端算法一致）
│   │       │       ├── ip-utils.js        # IP地址处理工具（网段匹配等）
│   │       │       ├── ui-handler.js      # 界面交互处理（表单验证、结果显示）
│   │       │       └── filter-engine.js   # 结果过滤和搜索功能
│   │       ├── templates/
│   │       │   └── web-demo.html          # Web演示页面模板（包含参数设置表单）
│   │       └── web_generator.py           # Web页面生成器（嵌入规则数据）
│   ├── data_access/         # 数据访问层
│   │   ├── iptables_dao.py      # iptables数据访问对象，使用python-iptables库解析规则
│   │   ├── ipvs_dao.py          # ipvs数据访问对象，通过ipvsadm命令获取负载均衡规则
│   │   └── k8s_client.py        # Kubernetes客户端，获取Service和Endpoint信息
│   ├── core/                # 核心算法层
│   │   ├── matching_engine.py   # 匹配引擎，实现IP/端口/协议匹配算法（集成扩展模块）
│   │   ├── table_processor.py   # 表处理器，按iptables表优先级处理规则
│   │   ├── report_generator.py  # 报告生成器，使用Jinja2模板生成分析报告
│   │   └── chart_generator.py   # 图表生成器，使用Graphviz生成网络拓扑图
│   ├── models/              # 数据模型层
│   │   ├── rule_models.py       # 规则数据模型，定义iptables/ipvs规则结构
│   │   └── traffic_models.py    # 流量数据模型，定义流量请求和模拟结果结构
│   ├── infrastructure/      # 基础设施层
│   │   ├── config.py            # 配置管理，支持YAML配置文件和环境变量
│   │   └── logger.py            # 日志服务，提供分级日志和文件输出功能
│   └── utils/               # 工具类
│       ├── ip_utils.py          # IP地址工具，提供网段匹配和IP验证功能
│       └── format_utils.py      # 格式化工具，提供数据格式转换和美化功能
├── tests/                   # 测试代码
│   ├── unit/                    # 单元测试，测试各个模块的独立功能
│   └── fixtures/                # 测试数据，提供模拟的iptables/ipvs规则数据
├── templates/               # 报告模板
│   ├── html/                    # HTML报告模板，使用Jinja2语法
│   └── markdown/                # Markdown报告模板，用于生成文档
├── config/                  # 配置文件
│   └── default.yaml             # 默认配置文件，定义解析器、模拟器、可视化参数
├── pyproject.toml          # 项目配置（uv管理），定义依赖和构建配置
├── build.py                # 单文件打包脚本，使用PyInstaller生成可执行文件
└── README.md               # 项目说明文档，包含使用方法和示例
```

### 发布阶段（单文件工具）
```
iptables-analyzer              # 单文件可执行程序，包含所有依赖，无需Python环境
├── config/                    # 配置文件（可选），用户可自定义解析和模拟参数
│   └── default.yaml              # 默认配置，定义解析器、模拟器、可视化参数
├── templates/                 # 报告模板（可选），用于生成自定义格式报告
│   ├── html/                     # HTML报告模板，支持交互式图表和样式
│   └── markdown/                 # Markdown报告模板，适合文档和版本控制
└── README.md                 # 使用说明文档，包含安装、配置和使用示例
```

---

## 技术选型说明

### 核心依赖
```toml
# pyproject.toml
[project]
name = "iptables-ipvs-analyzer"
version = "0.1.0"
description = "Linux iptables/ipvs数据包流向分析工具"
authors = [{name = "Your Name", email = "your.email@example.com"}]
readme = "README.md"
requires-python = ">=3.11"
dependencies = [
    "python-iptables>=0.14.0",    # iptables规则解析
    "typer>=0.9.0",               # CLI框架
    "jinja2>=3.1.0",              # 模板引擎
    "graphviz>=0.20.0",           # 图表生成
    "pyecharts>=1.9.0",           # 高级可视化（可选）
    "kubernetes>=24.0.0",         # K8s客户端（可选）
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",             # 测试框架
    "black>=22.0.0",              # 代码格式化
    "flake8>=5.0.0",              # 代码检查
    "mypy>=0.950",                # 类型检查
    "ruff>=0.1.0",                # 快速代码检查
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.uv]
dev-dependencies = [
    "pytest>=7.0.0",
    "black>=22.0.0",
    "flake8>=5.0.0",
    "mypy>=0.950",
    "ruff>=0.1.0",
]

[tool.black]
line-length = 88
target-version = ['py311']

[tool.ruff]
line-length = 88
target-version = "py311"

[tool.mypy]
python_version = "3.11"
warn_return_any = true
warn_unused_configs = true
```

### 设计模式

#### 1. 分层架构模式
- **用户接口层**：处理用户输入和输出
- **业务逻辑层**：实现核心业务功能
- **数据访问层**：封装数据访问逻辑
- **基础设施层**：提供通用服务

#### 2. 服务模式
- 每个服务负责特定的业务功能
- 服务之间通过接口通信
- 便于测试和维护

#### 3. 数据访问对象模式
- 封装数据访问逻辑
- 提供统一的数据接口
- 便于切换数据源

---

## 开发建议

### 1. 开发顺序
1. **第1周**：使用uv初始化项目，搭建单文件项目结构，实现基础模型
2. **第2-3周**：实现iptables解析功能
3. **第4-5周**：实现流量模拟功能
4. **第6-7周**：实现CLI接口和报告生成
5. **第8周**：集成测试和打包成单文件可执行程序

### 2. 测试策略
- **单元测试**：每个模块独立测试
- **集成测试**：模块间协作测试
- **端到端测试**：完整流程测试

### 3. 代码质量
- 使用类型提示
- 遵循PEP 8规范
- 编写清晰的文档字符串
- 保持函数简洁

### 4. 性能优化
- 优化数据结构选择
- 避免不必要的循环
- 使用生成器处理大数据
- 合理使用JSON文件存储和读取

### 5. 依赖管理
- 使用uv管理项目依赖，比pip更快更可靠
- 支持虚拟环境自动创建和管理
- 支持依赖锁定和版本管理

### 6. 单文件打包
- 使用PyInstaller或cx_Freeze打包成单文件可执行程序
- 包含所有依赖，无需安装Python环境
- 支持Linux系统直接运行

## 单文件工具实现示例

### 主程序结构
```python
#!/usr/bin/env python3.11
# -*- coding: utf-8 -*-
"""
iptables/ipvs 数据包流向分析工具
单文件版本 - 所有功能集成在一个可执行文件中
功能：提供三大核心功能 - 规则解析、流量演示、规则处理
特点：单文件部署，无需Python环境，支持Linux系统直接运行
Python 3.11+ 要求
"""

import sys
import json
import typer
from pathlib import Path
from typing import Optional, Literal

# 所有模块都集成在同一个文件中
# 或者使用相对导入（如果保持模块化结构）

def main():
    """主程序入口"""
    app = typer.Typer(
        name="iptables-analyzer",
        help="Linux iptables/ipvs数据包流向分析工具 - 单文件版本"
    )
    
    @app.command()
    def parse(
        output_file: Path = typer.Option("rules.json", "--output", "-o"),
        include_ipvs: bool = typer.Option(True, "--include-ipvs/--no-include-ipvs"),
        table: Optional[str] = typer.Option(None, "--table", "-t")
    ):
        """解析iptables/ipvs规则并保存到JSON文件
        功能：从系统获取防火墙和负载均衡规则，转换为标准JSON格式
        """
        # 实现解析逻辑
        pass
    
    @app.command()
    def demo(
        rules_file: Path = typer.Argument(..., help="规则JSON文件路径"),
        src_ip: str = typer.Argument(..., help="源IP地址"),
        dst_ip: str = typer.Argument(..., help="目标IP地址"),
        dst_port: int = typer.Argument(..., help="目标端口"),
        protocol: Literal["tcp", "udp", "icmp"] = typer.Argument(..., help="协议"),
        direction: Literal["inbound", "outbound", "forward"] = typer.Argument(..., help="流量方向"),
        output_format: Literal["text", "json"] = typer.Option("text", "--format", "-f")
    ):
        """命令行演示流量匹配过程
        功能：使用指定参数演示数据包通过iptables/ipvs规则的匹配过程
        """
        # 实现演示逻辑
        pass
    
    @app.command()
    def web_demo(
        output_file: Path = typer.Option("./demo.html", "--output", "-o", help="输出HTML文件路径"),
        default_rules: Path = typer.Option(None, "--default-rules", help="默认规则JSON文件路径（可选）")
    ):
        """生成Web交互式演示页面
        功能：生成支持文件上传的交互式静态网页，用户可上传JSON文件作为数据源并设置参数查看匹配结果
        """
        # 实现Web演示逻辑
        pass
    
    @app.command()
    def process(
        rules_file: Path = typer.Argument(..., help="规则JSON文件路径"),
        matched_rules: str = typer.Argument(..., help="匹配到的规则ID列表，用逗号分隔"),
        action: Literal["k8s-service", "report"] = typer.Argument(..., help="处理动作")
    ):
        """处理匹配到的规则（如关联K8s服务）
        功能：根据匹配结果进行后续处理，当前支持K8s服务关联
        """
        # 实现处理逻辑
        pass
    
    app()

if __name__ == "__main__":
    main()
```

### 打包配置
```python
# build.py - 单文件打包脚本
# 功能：使用PyInstaller将Python项目打包成单文件可执行程序
# 特点：集成uv环境管理，自动处理依赖，支持资源文件打包
import PyInstaller.__main__
import subprocess
import sys

def build():
    """使用uv环境打包单文件
    功能：检查uv环境，安装依赖，使用PyInstaller生成单文件可执行程序
    特点：自动处理隐藏导入，包含配置和模板文件，支持清理构建
    """
    # 确保在uv虚拟环境中
    try:
        subprocess.run(['uv', '--version'], check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("错误: 请先安装uv并激活虚拟环境")
        sys.exit(1)
    
    # 使用uv安装依赖
    subprocess.run(['uv', 'sync'], check=True)
    
    # 使用PyInstaller打包
    PyInstaller.__main__.run([
        'iptables_analyzer.py',
        '--onefile',
        '--name=iptables-analyzer',
        '--add-data=config:config',
        '--add-data=templates:templates',
        '--hidden-import=iptc',
        '--hidden-import=typer',
        '--hidden-import=jinja2',
        '--hidden-import=graphviz',
        '--clean',
        '--noconfirm'
    ])

if __name__ == "__main__":
    build()
```

### uv使用命令
```bash
# 初始化项目（指定Python 3.11）
uv init iptables-ipvs-analyzer --python 3.11
cd iptables-ipvs-analyzer

# 添加依赖
uv add python-iptables typer jinja2 graphviz
uv add --dev pytest black flake8 mypy ruff

# 安装依赖
uv sync

# 运行项目 - 四大核心功能
# 1. 解析规则
uv run python src/interfaces/cli/main.py parse --output rules.json

# 2. 命令行演示流量匹配
uv run python src/interfaces/cli/main.py demo rules.json 192.168.1.10 10.96.0.10 80 tcp outbound

# 3. 生成Web交互式演示页面
uv run python src/interfaces/cli/main.py web_demo --output demo.html
# 或者带默认规则文件
uv run python src/interfaces/cli/main.py web_demo --output demo.html --default-rules rules.json
# 生成 demo.html 文件，用浏览器打开即可上传JSON文件并交互式设置参数查看匹配结果

# 4. 处理匹配结果
uv run python src/interfaces/cli/main.py process rules.json "rule1,rule2,rule3" k8s-service

# 打包单文件
uv run python build.py
```

这个简化后的架构设计为您的个人开发项目提供了一个清晰、可维护的结构，专注于单文件工具的实现，使用uv进行高效的依赖管理，避免了复杂的部署和容器化配置。架构既保证了功能的完整性，又充分考虑了个人开发的实际情况，便于快速开发和迭代。

### uv的优势
- **速度更快**：比pip快10-100倍
- **依赖解析**：更智能的依赖冲突解决
- **虚拟环境**：自动创建和管理
- **锁定文件**：确保依赖版本一致性
- **现代工具**：支持最新的Python包管理标准

### Python 3.11的优势
- **性能提升**：比Python 3.8快10-60%
- **新语法特性**：支持更现代的Python语法
- **类型系统**：更好的类型提示支持
- **错误信息**：更清晰的错误提示和调试信息
- **标准库**：更多内置功能和优化
