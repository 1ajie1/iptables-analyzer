# -*- coding: utf-8 -*-
"""
iptables统一接口适配器
统一nf_tables和xt_tables接口，提供统一的规则访问
自动检测系统支持，优先使用nf_tables，降级到xt_tables
"""

import subprocess
from typing import List, Optional, Dict, Any
from src.data_access.nftables_dao import NftablesDAO
from src.models.rule_models import IptablesRule
from src.infrastructure.logger import logger
from src.infrastructure.error_handler import handle_parse_error


class IptablesAdapter:
    """iptables统一接口适配器"""
    
    def __init__(self, preferred_backend: str = "nftables"):
        """
        初始化适配器
        
        Args:
            preferred_backend: 首选后端 ("nftables", "xtables", "auto")
        """
        self.preferred_backend = preferred_backend
        self.nft_dao = None
        self.xt_dao = None
        self.available_backends = []
        self.current_backend = None
        
        # 初始化后端接口
        self._initialize_backends()
    
    def _initialize_backends(self):
        """初始化后端接口"""
        logger.info("正在初始化iptables后端接口...")
        
        # 尝试初始化nf_tables
        if self._detect_nftables_support():
            try:
                self.nft_dao = NftablesDAO()
                self.available_backends.append("nftables")
                logger.info("✅ nf_tables后端初始化成功")
            except Exception as e:
                logger.warning(f"❌ nf_tables后端初始化失败: {e}")
                self.nft_dao = None
        else:
            logger.info("❌ 系统不支持nf_tables")
        
        # 尝试初始化xt_tables（预留，当前版本不实现）
        if self._detect_xtables_support():
            try:
                # self.xt_dao = XtablesDAO()  # 后续版本实现
                # self.available_backends.append("xtables")
                logger.info("⚠️ xt_tables后端检测到但未实现（后续版本支持）")
            except Exception as e:
                logger.warning(f"❌ xt_tables后端初始化失败: {e}")
                self.xt_dao = None
        else:
            logger.info("❌ 系统不支持xt_tables或未安装python-iptables")
        
        # 设置当前使用的后端
        self._select_current_backend()
        
        logger.info(f"可用后端: {self.available_backends}")
        logger.info(f"当前使用后端: {self.current_backend}")
    
    def _detect_nftables_support(self) -> bool:
        """检测nf_tables支持"""
        try:
            # 检查nft命令是否存在
            result = subprocess.run(
                ['which', 'nft'], 
                capture_output=True, 
                text=True
            )
            if result.returncode != 0:
                logger.debug("nft命令不存在")
                return False
            
            # 检查nft命令是否能正常工作
            result = subprocess.run(
                ['nft', 'list', 'tables'], 
                capture_output=True, 
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                logger.debug(f"nft命令执行失败: {result.stderr}")
                return False
            
            logger.debug("nf_tables支持检测成功")
            return True
            
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.debug(f"nf_tables支持检测失败: {e}")
            return False
        except Exception as e:
            logger.debug(f"nf_tables支持检测异常: {e}")
            return False
    
    def _detect_xtables_support(self) -> bool:
        """检测xt_tables支持"""
        try:
            # 检查iptables命令是否存在
            result = subprocess.run(
                ['which', 'iptables'], 
                capture_output=True, 
                text=True
            )
            if result.returncode != 0:
                logger.debug("iptables命令不存在")
                return False
            
            # 检查python-iptables库是否可用
            try:
                import iptc  # noqa: F401
                logger.debug("python-iptables库检测成功")
                return True
            except ImportError:
                logger.debug("python-iptables库未安装")
                return False
            
        except Exception as e:
            logger.debug(f"xt_tables支持检测异常: {e}")
            return False
    
    def _select_current_backend(self):
        """选择当前使用的后端"""
        if self.preferred_backend == "auto":
            # 自动选择：优先nftables，降级到xtables
            if "nftables" in self.available_backends:
                self.current_backend = "nftables"
            elif "xtables" in self.available_backends:
                self.current_backend = "xtables"
            else:
                self.current_backend = None
        
        elif self.preferred_backend == "nftables":
            if "nftables" in self.available_backends:
                self.current_backend = "nftables"
            elif "xtables" in self.available_backends:
                logger.warning("首选nftables不可用，降级到xtables")
                self.current_backend = "xtables"
            else:
                self.current_backend = None
        
        elif self.preferred_backend == "xtables":
            if "xtables" in self.available_backends:
                self.current_backend = "xtables"
            elif "nftables" in self.available_backends:
                logger.warning("首选xtables不可用，使用nftables")
                self.current_backend = "nftables"
            else:
                self.current_backend = None
        
        else:
            logger.error(f"不支持的后端类型: {self.preferred_backend}")
            self.current_backend = None
    
    @handle_parse_error
    def get_rules(self, table: Optional[str] = None) -> List[IptablesRule]:
        """
        获取iptables规则（统一接口）
        
        Args:
            table: 指定表名，None表示获取所有表
            
        Returns:
            IptablesRule对象列表
            
        Raises:
            RuntimeError: 没有可用的后端接口
        """
        if not self.current_backend:
            raise RuntimeError("没有可用的iptables后端接口")
        
        logger.info(f"使用 {self.current_backend} 后端获取规则")
        
        # 尝试使用当前后端
        try:
            if self.current_backend == "nftables" and self.nft_dao:
                return self.nft_dao.get_rules(table)
            
            elif self.current_backend == "xtables" and self.xt_dao:
                return self.xt_dao.get_rules(table)
            
            else:
                raise RuntimeError(f"后端 {self.current_backend} 不可用")
        
        except Exception as e:
            logger.error(f"{self.current_backend} 后端失败: {e}")
            
            # 尝试降级到其他后端
            return self._try_fallback_backend(table, e)
    
    def _try_fallback_backend(self, table: Optional[str], original_error: Exception) -> List[IptablesRule]:
        """尝试降级到其他后端"""
        fallback_backend = None
        
        # 确定降级后端
        if self.current_backend == "nftables" and "xtables" in self.available_backends:
            fallback_backend = "xtables"
        elif self.current_backend == "xtables" and "nftables" in self.available_backends:
            fallback_backend = "nftables"
        
        if not fallback_backend:
            logger.error("没有可用的降级后端")
            raise RuntimeError(f"所有后端都不可用，原始错误: {original_error}")
        
        logger.warning(f"降级到 {fallback_backend} 后端")
        
        try:
            if fallback_backend == "nftables" and self.nft_dao:
                return self.nft_dao.get_rules(table)
            elif fallback_backend == "xtables" and self.xt_dao:
                return self.xt_dao.get_rules(table)
            else:
                raise RuntimeError(f"降级后端 {fallback_backend} 不可用")
        
        except Exception as fallback_error:
            logger.error(f"降级后端也失败: {fallback_error}")
            raise RuntimeError(f"所有后端都失败，原始错误: {original_error}，降级错误: {fallback_error}")
    
    def get_available_backends(self) -> List[str]:
        """获取可用的后端接口列表"""
        return self.available_backends.copy()
    
    def get_current_backend(self) -> Optional[str]:
        """获取当前使用的后端"""
        return self.current_backend
    
    def set_preferred_backend(self, backend: str):
        """
        设置首选后端接口
        
        Args:
            backend: 后端类型 ("nftables", "xtables", "auto")
        """
        if backend not in ["nftables", "xtables", "auto"]:
            raise ValueError(f"不支持的后端类型: {backend}")
        
        self.preferred_backend = backend
        self._select_current_backend()
        
        logger.info(f"首选后端设置为: {backend}")
        logger.info(f"当前使用后端: {self.current_backend}")
    
    def get_backend_info(self) -> Dict[str, Any]:
        """获取后端信息"""
        info = {
            "preferred_backend": self.preferred_backend,
            "current_backend": self.current_backend,
            "available_backends": self.available_backends,
            "nftables_available": "nftables" in self.available_backends,
            "xtables_available": "xtables" in self.available_backends,
        }
        
        # 添加版本信息
        if "nftables" in self.available_backends:
            info["nftables_version"] = self._get_nftables_version()
        
        if "xtables" in self.available_backends:
            info["xtables_version"] = self._get_xtables_version()
        
        return info
    
    def _get_nftables_version(self) -> Optional[str]:
        """获取nftables版本"""
        try:
            result = subprocess.run(
                ['nft', '--version'], 
                capture_output=True, 
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                # 解析版本信息，例如: "nftables v1.0.6 (Lester Gooch #5)"
                version_line = result.stdout.strip().split('\n')[0]
                return version_line
            return None
        except Exception:
            return None
    
    def _get_xtables_version(self) -> Optional[str]:
        """获取xtables版本"""
        try:
            result = subprocess.run(
                ['iptables', '--version'], 
                capture_output=True, 
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                # 解析版本信息，例如: "iptables v1.8.7 (nf_tables)"
                version_line = result.stdout.strip().split('\n')[0]
                return version_line
            return None
        except Exception:
            return None
    
    def get_available_tables(self) -> List[str]:
        """获取可用的表列表"""
        if not self.current_backend:
            return []
        
        try:
            if self.current_backend == "nftables" and self.nft_dao:
                return self.nft_dao.get_available_tables()
            elif self.current_backend == "xtables" and self.xt_dao:
                return self.xt_dao.get_available_tables()
            else:
                return []
        except Exception as e:
            logger.error(f"获取可用表列表失败: {e}")
            return []
    
    def health_check(self) -> Dict[str, Any]:
        """健康检查"""
        health = {
            "status": "healthy",
            "backend_info": self.get_backend_info(),
            "checks": {}
        }
        
        # 检查nftables
        if "nftables" in self.available_backends:
            try:
                if self.nft_dao:
                    tables = self.nft_dao.get_available_tables()
                    health["checks"]["nftables"] = {
                        "status": "ok",
                        "available_tables": len(tables),
                        "tables": tables
                    }
                else:
                    health["checks"]["nftables"] = {
                        "status": "error",
                        "error": "DAO not initialized"
                    }
            except Exception as e:
                health["checks"]["nftables"] = {
                    "status": "error",
                    "error": str(e)
                }
        
        # 检查xtables（预留）
        if "xtables" in self.available_backends:
            health["checks"]["xtables"] = {
                "status": "not_implemented",
                "message": "xt_tables backend not implemented yet"
            }
        
        # 确定整体状态
        if not self.available_backends:
            health["status"] = "unhealthy"
            health["message"] = "No available backends"
        elif not self.current_backend:
            health["status"] = "unhealthy"
            health["message"] = "No current backend selected"
        
        return health
    
    def reload_backends(self):
        """重新加载后端接口"""
        logger.info("重新加载后端接口...")
        
        # 清理现有状态
        self.nft_dao = None
        self.xt_dao = None
        self.available_backends = []
        self.current_backend = None
        
        # 重新初始化
        self._initialize_backends()
        
        logger.info("后端接口重新加载完成")
    
    def __str__(self) -> str:
        """字符串表示"""
        return f"IptablesAdapter(current={self.current_backend}, available={self.available_backends})"
    
    def __repr__(self) -> str:
        """详细字符串表示"""
        return (f"IptablesAdapter(preferred={self.preferred_backend}, "
                f"current={self.current_backend}, available={self.available_backends})")
