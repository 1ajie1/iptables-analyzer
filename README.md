# iptables/ipvs 数据包流向分析工具

一个用于分析Linux iptables和ipvs规则的工具，帮助理解数据包在网络中的流向。

## 功能特性

### v1.0版本（核心功能）
- **规则解析**：从系统获取iptables/ipvs规则，生成结构化JSON文件
- **流量演示**：命令行演示流量匹配过程，支持多种输出格式
- **规则处理**：对匹配到的规则进行后续处理，支持K8s服务关联

### v2.0版本（扩展功能）
- **Web演示**：生成交互式静态网页，支持文件上传和参数设置

## 快速开始

### 环境要求
- Linux系统（Ubuntu 20.04+, CentOS 7+, Rocky Linux 8+）
- Python 3.11+
- root权限（用于读取iptables/ipvs规则）

### 安装依赖
```bash
# 安装uv（如果未安装）
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc

# 安装项目依赖
uv sync
```

### 使用方法

#### 1. 解析规则
```bash
# 解析所有规则
uv run python src/interfaces/cli/main.py parse --output rules.json

# 只解析iptables规则
uv run python src/interfaces/cli/main.py parse --no-include-ipvs --output iptables.json

# 只解析特定表
uv run python src/interfaces/cli/main.py parse --table filter --output filter.json
```

#### 2. 流量演示
```bash
# 演示流量匹配
uv run python src/interfaces/cli/main.py demo rules.json 192.168.1.10 10.96.0.10 80 tcp outbound

# JSON格式输出
uv run python src/interfaces/cli/main.py demo rules.json 192.168.1.10 10.96.0.10 80 tcp outbound --format json
```

#### 3. 规则处理
```bash
# 关联K8s服务
uv run python src/interfaces/cli/main.py process rules.json "1,2,3" k8s-service

# 生成处理报告
uv run python src/interfaces/cli/main.py process rules.json "1,2,3" report
```

## 项目结构

```
iptables-ipvs-analyzer/
├── src/                    # 源代码
│   ├── interfaces/         # 用户接口层
│   │   └── cli/           # CLI接口
│   ├── services/          # 核心功能层
│   ├── demo/              # 流量演示模块
│   ├── data_access/       # 数据访问层
│   ├── core/              # 核心算法层
│   ├── models/            # 数据模型层
│   ├── infrastructure/    # 基础设施层
│   └── utils/             # 工具类
├── tests/                 # 测试代码
├── templates/             # 报告模板
├── config/                # 配置文件
├── pyproject.toml         # 项目配置
├── build.py              # 打包脚本
└── README.md             # 项目说明
```

## 开发指南

### 开发环境搭建
```bash
# 克隆项目
git clone <your-repo-url> iptables-ipvs-analyzer
cd iptables-ipvs-analyzer

# 初始化项目环境
uv init --python 3.11
uv add python-iptables typer jinja2 graphviz
uv add --dev pytest black flake8 mypy ruff

# 安装依赖
uv sync
```

### 运行测试
```bash
# 运行所有测试
uv run pytest tests/

# 运行特定测试
uv run pytest tests/unit/test_parser.py -v

# 运行测试并生成覆盖率报告
uv run pytest tests/ --cov=src --cov-report=html
```

### 代码质量检查
```bash
# 代码格式化
uv run black src/

# 代码检查
uv run ruff check src/

# 类型检查
uv run mypy src/
```

### 单文件打包
```bash
# 构建可执行文件
uv run python build.py

# 测试可执行文件
./dist/iptables-analyzer --help
```

## 配置说明

配置文件位于 `config/default.yaml`，包含以下配置项：

- **parser**: 解析器配置（iptables、ipvs、k8s）
- **simulator**: 模拟器配置（性能、匹配模式）
- **visualization**: 可视化配置（图表、报告）
- **logging**: 日志配置（级别、输出）

## 贡献指南

1. Fork 项目
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开 Pull Request

## 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 联系方式

如有问题或建议，请通过以下方式联系：

- 提交 Issue
- 发送邮件到 your.email@example.com