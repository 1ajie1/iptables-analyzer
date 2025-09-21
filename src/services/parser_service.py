# -*- coding: utf-8 -*-
"""
规则解析服务
整合多个数据源，提供统一的规则解析接口
支持iptables/ipvs/K8s数据源，规则标准化，K8s资源关联
"""

import json
import platform
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

from src.data_access.iptables_adapter import IptablesAdapter
from src.models.rule_models import IptablesRule, RuleSet
from src.infrastructure.logger import logger
from src.infrastructure.error_handler import handle_parse_error
from src.infrastructure.config import Config


class ParserService:
    """规则解析服务"""
    
    def __init__(self, config: Optional[Config] = None):
        """
        初始化解析服务
        
        Args:
            config: 配置对象，如果为None则使用默认配置
        """
        self.config = config or Config()
        self.iptables_adapter = None
        # self.ipvs_dao = None  # 后续版本实现
        # self.k8s_client = None  # 后续版本实现
        
        # 初始化组件
        self._initialize_components()
    
    def _initialize_components(self):
        """初始化各组件"""
        logger.info("正在初始化解析服务组件...")
        
        # 初始化iptables适配器
        try:
            iptables_config = self.config.get('parser.iptables', {})
            preferred_backend = iptables_config.get('backend', 'nftables')
            
            self.iptables_adapter = IptablesAdapter(preferred_backend)
            logger.info(f"✅ iptables适配器初始化成功，使用后端: {self.iptables_adapter.get_current_backend()}")
            
        except Exception as e:
            logger.error(f"❌ iptables适配器初始化失败: {e}")
            self.iptables_adapter = None
        
        # TODO: 初始化ipvs DAO（后续版本）
        # TODO: 初始化K8s客户端（后续版本）
        
        logger.info("解析服务组件初始化完成")
    
    @handle_parse_error
    def parse_rules(
        self, 
        include_ipvs: bool = True, 
        table: Optional[str] = None,
        output_file: Optional[str] = None
    ) -> RuleSet:
        """
        解析所有规则
        
        Args:
            include_ipvs: 是否包含ipvs规则
            table: 指定iptables表名，None表示获取所有表
            output_file: 输出文件路径，如果提供则保存到文件
            
        Returns:
            RuleSet对象，包含所有解析后的规则
        """
        logger.info("开始解析规则...")
        logger.info(f"参数: include_ipvs={include_ipvs}, table={table}, output_file={output_file}")
        
        # 创建规则集
        ruleset = RuleSet(
            metadata=self._generate_metadata(),
            iptables_rules={},
            ipvs_rules={"virtual_services": []}
        )
        
        # 解析iptables规则
        if self.iptables_adapter:
            try:
                iptables_rules = self._parse_iptables_rules(table)
                ruleset.iptables_rules = self._organize_iptables_rules(iptables_rules)
                
                rules_count = sum(
                    sum(len(chain_data.get('rules', [])) for chain_data in table_data.values())
                    for table_data in ruleset.iptables_rules.values()
                )
                logger.info(f"✅ iptables规则解析完成，共 {rules_count} 条规则")
                
            except Exception as e:
                logger.error(f"❌ iptables规则解析失败: {e}")
                # 继续处理其他规则类型
        else:
            logger.warning("iptables适配器不可用，跳过iptables规则解析")
        
        # TODO: 解析ipvs规则（后续版本）
        if include_ipvs:
            logger.info("⚠️ ipvs规则解析功能将在后续版本实现")
        
        # TODO: 关联K8s资源（后续版本）
        # self._associate_k8s_resources(ruleset)
        
        # 保存到文件
        if output_file:
            self._save_ruleset_to_file(ruleset, output_file)
        
        logger.info("规则解析完成")
        return ruleset
    
    def _parse_iptables_rules(self, table: Optional[str] = None) -> List[IptablesRule]:
        """解析iptables规则"""
        if not self.iptables_adapter:
            raise RuntimeError("iptables适配器未初始化")
        
        logger.info(f"开始解析iptables规则，表: {table or 'all'}")
        
        # 获取配置的表列表
        configured_tables = self.config.get('parser.iptables.tables', ['raw', 'mangle', 'nat', 'filter'])
        
        if table:
            if table not in configured_tables:
                logger.warning(f"表 {table} 不在配置的表列表中: {configured_tables}")
            rules = self.iptables_adapter.get_rules(table)
        else:
            # 按配置的表顺序解析
            all_rules = []
            for table_name in configured_tables:
                try:
                    table_rules = self.iptables_adapter.get_rules(table_name)
                    all_rules.extend(table_rules)
                    logger.debug(f"表 {table_name}: {len(table_rules)} 条规则")
                except Exception as e:
                    logger.warning(f"解析表 {table_name} 失败: {e}")
                    continue
            rules = all_rules
        
        logger.info(f"iptables规则解析完成，共 {len(rules)} 条规则")
        return rules
    
    def _organize_iptables_rules(self, rules: List[IptablesRule]) -> Dict[str, Any]:
        """组织iptables规则为标准JSON格式"""
        organized_rules = {}
        
        # 按表和链分组规则
        for rule in rules:
            # 从rule_id中提取表名和链名
            parts = rule.rule_id.split('_')
            if len(parts) >= 2:
                table_name = parts[0]
                chain_name = parts[1]
            else:
                logger.warning(f"无法解析规则ID: {rule.rule_id}")
                continue
            
            # 确保表存在
            if table_name not in organized_rules:
                organized_rules[table_name] = {}
            
            # 确保链存在
            if chain_name not in organized_rules[table_name]:
                organized_rules[table_name][chain_name] = {
                    'default_policy': 'ACCEPT',  # 默认策略，实际应该从系统获取
                    'rules': []
                }
            
            # 添加规则
            rule_dict = {
                'rule_id': rule.rule_id,
                'match_conditions': {
                    'source_ip': rule.match_conditions.source_ip,
                    'destination_ip': rule.match_conditions.destination_ip,
                    'protocol': rule.match_conditions.protocol,
                    'source_port': rule.match_conditions.source_port,
                    'destination_port': rule.match_conditions.destination_port,
                    'in_interface': rule.match_conditions.in_interface,
                    'out_interface': rule.match_conditions.out_interface,
                    'state': rule.match_conditions.state
                },
                'action': rule.action,
                'jump_chain': rule.jump_chain,
                'target': rule.target
            }
            
            organized_rules[table_name][chain_name]['rules'].append(rule_dict)
        
        # 确保所有配置的表都存在（即使是空的）
        configured_tables = self.config.get('parser.iptables.tables', ['raw', 'mangle', 'nat', 'filter'])
        for table_name in configured_tables:
            if table_name not in organized_rules:
                organized_rules[table_name] = {}
        
        return organized_rules
    
    def _generate_metadata(self) -> Dict[str, Any]:
        """生成元数据"""
        metadata = {
            'generated_at': datetime.now().isoformat(),
            'tool_version': '0.1.0',
            'environment': {
                'os': platform.system(),
                'kernel_version': platform.release(),
                'architecture': platform.machine(),
                'python_version': platform.python_version()
            },
            'parser_info': {
                'backend_used': None,
                'available_backends': [],
                'backend_versions': {}
            }
        }
        
        # 添加后端信息
        if self.iptables_adapter:
            backend_info = self.iptables_adapter.get_backend_info()
            metadata['parser_info']['backend_used'] = backend_info.get('current_backend')
            metadata['parser_info']['available_backends'] = backend_info.get('available_backends', [])
            
            # 添加版本信息
            if 'nftables_version' in backend_info:
                metadata['parser_info']['backend_versions']['nftables'] = backend_info['nftables_version']
            if 'xtables_version' in backend_info:
                metadata['parser_info']['backend_versions']['xtables'] = backend_info['xtables_version']
        
        return metadata
    
    def _save_ruleset_to_file(self, ruleset: RuleSet, output_file: str):
        """保存规则集到文件"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # 转换为字典格式
            ruleset_dict = ruleset.to_dict()
            
            # 保存为JSON文件
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(ruleset_dict, f, indent=2, ensure_ascii=False)
            
            logger.info(f"✅ 规则集已保存到: {output_path}")
            
        except Exception as e:
            logger.error(f"❌ 保存规则集失败: {e}")
            raise
    
    def get_parser_status(self) -> Dict[str, Any]:
        """获取解析器状态"""
        status = {
            'service_status': 'initialized',
            'components': {},
            'configuration': {
                'iptables_enabled': self.config.get('parser.iptables.enabled', True),
                'iptables_tables': self.config.get('parser.iptables.tables', []),
                'iptables_backend': self.config.get('parser.iptables.backend', 'nftables'),
                'ipvs_enabled': self.config.get('parser.ipvs.enabled', True),
                'k8s_enabled': self.config.get('parser.k8s.enabled', True),
            }
        }
        
        # iptables组件状态
        if self.iptables_adapter:
            try:
                health = self.iptables_adapter.health_check()
                status['components']['iptables'] = {
                    'status': 'healthy' if health['status'] == 'healthy' else 'unhealthy',
                    'backend': self.iptables_adapter.get_current_backend(),
                    'available_backends': self.iptables_adapter.get_available_backends(),
                    'available_tables': self.iptables_adapter.get_available_tables(),
                    'health_details': health
                }
            except Exception as e:
                status['components']['iptables'] = {
                    'status': 'error',
                    'error': str(e)
                }
        else:
            status['components']['iptables'] = {
                'status': 'not_initialized'
            }
        
        # TODO: ipvs组件状态（后续版本）
        status['components']['ipvs'] = {
            'status': 'not_implemented',
            'message': 'ipvs support will be implemented in future versions'
        }
        
        # TODO: K8s组件状态（后续版本）
        status['components']['k8s'] = {
            'status': 'not_implemented',
            'message': 'K8s support will be implemented in future versions'
        }
        
        return status
    
    def validate_configuration(self) -> Dict[str, Any]:
        """验证配置"""
        validation_result = {
            'valid': True,
            'warnings': [],
            'errors': []
        }
        
        # 验证iptables配置
        iptables_config = self.config.get('parser.iptables', {})
        
        # 检查后端配置
        backend = iptables_config.get('backend', 'nftables')
        if backend not in ['nftables', 'xtables', 'auto']:
            validation_result['errors'].append(f"无效的iptables后端配置: {backend}")
            validation_result['valid'] = False
        
        # 检查表配置
        tables = iptables_config.get('tables', [])
        valid_tables = ['raw', 'mangle', 'nat', 'filter']
        for table in tables:
            if table not in valid_tables:
                validation_result['warnings'].append(f"未知的iptables表: {table}")
        
        # 检查是否启用了任何解析功能
        if not any([
            self.config.get('parser.iptables.enabled', True),
            self.config.get('parser.ipvs.enabled', True),
            self.config.get('parser.k8s.enabled', True)
        ]):
            validation_result['warnings'].append("所有解析功能都被禁用")
        
        return validation_result
    
    def reload_configuration(self, new_config: Optional[Config] = None):
        """重新加载配置"""
        logger.info("重新加载解析服务配置...")
        
        if new_config:
            self.config = new_config
        else:
            self.config.reload()
        
        # 重新初始化组件
        self._initialize_components()
        
        logger.info("配置重新加载完成")
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        stats = {
            'service_info': {
                'version': '0.1.0',
                'initialized_at': datetime.now().isoformat(),
                'configuration_source': str(self.config.config_file) if hasattr(self.config, 'config_file') else 'default'
            },
            'capabilities': {
                'iptables_parsing': self.iptables_adapter is not None,
                'ipvs_parsing': False,  # 后续版本
                'k8s_integration': False,  # 后续版本
                'supported_backends': self.iptables_adapter.get_available_backends() if self.iptables_adapter else []
            }
        }
        
        # 添加后端统计
        if self.iptables_adapter:
            try:
                backend_info = self.iptables_adapter.get_backend_info()
                stats['backend_statistics'] = backend_info
            except Exception as e:
                stats['backend_statistics'] = {'error': str(e)}
        
        return stats
    
    def __str__(self) -> str:
        """字符串表示"""
        backend = self.iptables_adapter.get_current_backend() if self.iptables_adapter else 'none'
        return f"ParserService(backend={backend})"
    
    def __repr__(self) -> str:
        """详细字符串表示"""
        return (f"ParserService("
                f"iptables_adapter={self.iptables_adapter is not None}, "
                f"config_file={getattr(self.config, 'config_file', 'default')}"
                f")")
