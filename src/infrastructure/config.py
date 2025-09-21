# -*- coding: utf-8 -*-
"""
配置管理模块
管理应用程序配置，支持YAML文件和环境变量
"""

import yaml
from pathlib import Path
from typing import Dict, Any


class Config:
    """配置管理类"""
    
    def __init__(self, config_file: str = "config/default.yaml"):
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
                    'enabled': True,
                    'tables': ['raw', 'mangle', 'nat', 'filter']
                },
                'ipvs': {
                    'enabled': True
                },
                'k8s': {
                    'enabled': True,
                    'config_path': '~/.kube/config'
                }
            },
            'simulator': {
                'matching': {
                    'strict_mode': False,
                    'debug_mode': False
                }
            },
            'visualization': {
                'charts': {
                    'max_rules_display': 1000,
                    'theme': 'light'
                },
                'reports': {
                    'output_format': 'html',
                    'include_charts': True
                }
            },
            'logging': {
                'level': 'INFO',
                'file': None,
                'console': True
            }
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """获取配置值"""
        keys = key.split('.')
        value = self._config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any):
        """设置配置值"""
        keys = key.split('.')
        config = self._config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def save(self):
        """保存配置到文件"""
        with open(self.config_file, 'w', encoding='utf-8') as f:
            yaml.dump(self._config, f, default_flow_style=False, allow_unicode=True)
    
    def reload(self):
        """重新加载配置"""
        self._config = self._load_config()
