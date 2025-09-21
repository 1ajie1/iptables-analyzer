# -*- coding: utf-8 -*-
"""
IP地址处理工具
提供网段匹配和IP验证功能
"""

import ipaddress
from typing import  List

class IPUtils:
    """IP地址处理工具类"""
    
    @staticmethod
    def is_ip_in_network(ip: str, network: str) -> bool:
        """检查IP是否在网段内"""
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(network)
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """验证IP地址格式"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_network(network: str) -> bool:
        """验证网段格式"""
        try:
            ipaddress.ip_network(network)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def normalize_ip(ip: str) -> str:
        """标准化IP地址格式"""
        try:
            return str(ipaddress.ip_address(ip))
        except ValueError:
            return ip
    
    @staticmethod
    def normalize_network(network: str) -> str:
        """标准化网段格式"""
        try:
            return str(ipaddress.ip_network(network))
        except ValueError:
            return network
    
    @staticmethod
    def get_network_info(network: str) -> dict:
        """获取网段信息"""
        try:
            net = ipaddress.ip_network(network)
            return {
                'network': str(net),
                'netmask': str(net.netmask),
                'broadcast': str(net.broadcast_address),
                'num_addresses': net.num_addresses,
                'version': net.version
            }
        except ValueError:
            return {}
    
    @staticmethod
    def match_ip_list(ip: str, ip_list: List[str]) -> bool:
        """检查IP是否匹配列表中的任意一个"""
        for ip_pattern in ip_list:
            if IPUtils.is_ip_in_network(ip, ip_pattern):
                return True
        return False
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """检查是否为私有IP"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False
    
    @staticmethod
    def is_loopback_ip(ip: str) -> bool:
        """检查是否为回环IP"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_loopback
        except ValueError:
            return False
    
    @staticmethod
    def is_multicast_ip(ip: str) -> bool:
        """检查是否为组播IP"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_multicast
        except ValueError:
            return False
