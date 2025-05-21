from datetime import datetime
from typing import Dict, List, Any, Optional
from enum import Enum

class ContentType(str, Enum):
    EMAIL = "email"
    DOCUMENT = "document"
    SPREADSHEET = "spreadsheet"
    PRESENTATION = "presentation"
    PDF = "pdf"
    IMAGE = "image"
    OTHER = "other"

class ProcessingStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"

class SensitivityLevel(str, Enum):
    GENERAL = "general"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SENSITIVE = "sensitive"

class AccessStatus(str, Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    PENDING_REVIEW = "pending_review"

class ContentItem:
    """
    MongoDB model for a content item (document, email, etc.)
    """
    def __init__(
        self,
        id: Optional[str] = None,
        title: str = "",
        source: str = "",
        org_id: str = "",
        content_type: ContentType = ContentType.OTHER,
        file_path: Optional[str] = None,
        file_size: Optional[int] = None,
        md5_hash: Optional[str] = None,
        sha256_hash: Optional[str] = None,
        created_at: Optional[datetime] = None,
        updated_at: Optional[datetime] = None,
        processing_status: ProcessingStatus = ProcessingStatus.PENDING,
        processing_error: Optional[str] = None,
        metadata: Dict[str, Any] = None,
        content_metadata: Dict[str, Any] = None,
        raw_content: Optional[str] = None,
        clean_content: Optional[str] = None,
        sensitivity_level: SensitivityLevel = SensitivityLevel.GENERAL,
        access_status: AccessStatus = AccessStatus.ALLOWED,
        yara_matches: List[Dict[str, Any]] = None,
        keyword_matches: Dict[str, List[str]] = None,
        entity_matches: Dict[str, List[Dict[str, Any]]] = None,
        llm_analysis: Dict[str, Any] = None,
        embedding_id: Optional[str] = None,
        related_content_ids: List[str] = None,
        tags: List[str] = None
    ):
        self.id = id
        self.title = title
        self.source = source
        self.org_id = org_id
        self.content_type = content_type
        self.file_path = file_path
        self.file_size = file_size
        self.md5_hash = md5_hash
        self.sha256_hash = sha256_hash
        self.created_at = created_at or datetime.now()
        self.updated_at = updated_at or datetime.now()
        self.processing_status = processing_status
        self.processing_error = processing_error
        self.metadata = metadata or {}
        self.content_metadata = content_metadata or {}
        self.raw_content = raw_content
        self.clean_content = clean_content
        self.sensitivity_level = sensitivity_level
        self.access_status = access_status
        self.yara_matches = yara_matches or []
        self.keyword_matches = keyword_matches or {}
        self.entity_matches = entity_matches or {}
        self.llm_analysis = llm_analysis or {}
        self.embedding_id = embedding_id
        self.related_content_ids = related_content_ids or []
        self.tags = tags or []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for MongoDB storage"""
        return {
            "_id": self.id,
            "title": self.title,
            "source": self.source,
            "org_id": self.org_id,
            "content_type": self.content_type,
            "file_path": self.file_path,
            "file_size": self.file_size,
            "md5_hash": self.md5_hash,
            "sha256_hash": self.sha256_hash,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "processing_status": self.processing_status,
            "processing_error": self.processing_error,
            "metadata": self.metadata,
            "content_metadata": self.content_metadata,
            "raw_content": self.raw_content,
            "clean_content": self.clean_content,
            "sensitivity_level": self.sensitivity_level,
            "access_status": self.access_status,
            "yara_matches": self.yara_matches,
            "keyword_matches": self.keyword_matches,
            "entity_matches": self.entity_matches,
            "llm_analysis": self.llm_analysis,
            "embedding_id": self.embedding_id,
            "related_content_ids": self.related_content_ids,
            "tags": self.tags
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ContentItem':
        """Create from MongoDB dictionary"""
        id_val = data.pop("_id", None)
        return cls(id=id_val, **data)

class YaraRule:
    """
    MongoDB model for a YARA rule
    """
    def __init__(
        self,
        id: Optional[str] = None,
        name: str = "",
        description: str = "",
        org_id: str = "",
        project_id: Optional[str] = None,
        rule_content: str = "",
        compiled_path: Optional[str] = None,
        instance_id: Optional[str] = None,
        created_by: str = "",
        created_at: Optional[datetime] = None,
        updated_at: Optional[datetime] = None,
        is_active: bool = True,
        metadata: Dict[str, Any] = None,
        match_count: int = 0,
        false_positive_count: int = 0,
        tags: List[str] = None
    ):
        self.id = id
        self.name = name
        self.description = description
        self.org_id = org_id
        self.project_id = project_id
        self.rule_content = rule_content
        self.compiled_path = compiled_path
        self.instance_id = instance_id
        self.created_by = created_by
        self.created_at = created_at or datetime.now()
        self.updated_at = updated_at or datetime.now()
        self.is_active = is_active
        self.metadata = metadata or {}
        self.match_count = match_count
        self.false_positive_count = false_positive_count
        self.tags = tags or []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for MongoDB storage"""
        return {
            "_id": self.id,
            "name": self.name,
            "description": self.description,
            "org_id": self.org_id,
            "project_id": self.project_id,
            "rule_content": self.rule_content,
            "compiled_path": self.compiled_path,
            "instance_id": self.instance_id,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "is_active": self.is_active,
            "metadata": self.metadata,
            "match_count": self.match_count,
            "false_positive_count": self.false_positive_count,
            "tags": self.tags
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'YaraRule':
        """Create from MongoDB dictionary"""
        id_val = data.pop("_id", None)
        return cls(id=id_val, **data)

class User:
    """
    MongoDB model for a user
    """
    def __init__(
        self,
        id: Optional[str] = None,
        username: str = "",
        email: str = "",
        full_name: str = "",
        org_id: str = "",
        role: str = "employee",
        roles: List[str] = None,
        created_at: Optional[datetime] = None,
        updated_at: Optional[datetime] = None,
        is_active: bool = True,
        last_login: Optional[datetime] = None,
        preferences: Dict[str, Any] = None,
        permissions: Dict[str, bool] = None
    ):
        self.id = id
        self.username = username
        self.email = email
        self.full_name = full_name
        self.org_id = org_id
        self.role = role
        self.roles = roles or [role]
        self.created_at = created_at or datetime.now()
        self.updated_at = updated_at or datetime.now()
        self.is_active = is_active
        self.last_login = last_login
        self.preferences = preferences or {}
        self.permissions = permissions or {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for MongoDB storage"""
        return {
            "_id": self.id,
            "username": self.username,
            "email": self.email,
            "full_name": self.full_name,
            "org_id": self.org_id,
            "role": self.role,
            "roles": self.roles,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "is_active": self.is_active,
            "last_login": self.last_login,
            "preferences": self.preferences,
            "permissions": self.permissions
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'User':
        """Create from MongoDB dictionary"""
        id_val = data.pop("_id", None)
        return cls(id=id_val, **data)

class Organization:
    """
    MongoDB model for an organization
    """
    def __init__(
        self,
        id: Optional[str] = None,
        name: str = "",
        display_name: str = "",
        created_at: Optional[datetime] = None,
        updated_at: Optional[datetime] = None,
        is_active: bool = True,
        settings: Dict[str, Any] = None,
        tenant_id: Optional[str] = None,
        api_keys: List[Dict[str, Any]] = None
    ):
        self.id = id
        self.name = name
        self.display_name = display_name
        self.created_at = created_at or datetime.now()
        self.updated_at = updated_at or datetime.now()
        self.is_active = is_active
        self.settings = settings or {}
        self.tenant_id = tenant_id
        self.api_keys = api_keys or []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for MongoDB storage"""
        return {
            "_id": self.id,
            "name": self.name,
            "display_name": self.display_name,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "is_active": self.is_active,
            "settings": self.settings,
            "tenant_id": self.tenant_id,
            "api_keys": self.api_keys
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Organization':
        """Create from MongoDB dictionary"""
        id_val = data.pop("_id", None)
        return cls(id=id_val, **data)

class AuditLog:
    """
    MongoDB model for an audit log entry
    """
    def __init__(
        self,
        id: Optional[str] = None,
        action: str = "",
        user_id: str = "",
        org_id: str = "",
        target_type: str = "",
        target_id: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        details: Dict[str, Any] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_id: Optional[str] = None
    ):
        self.id = id
        self.action = action
        self.user_id = user_id
        self.org_id = org_id
        self.target_type = target_type
        self.target_id = target_id
        self.timestamp = timestamp or datetime.now()
        self.details = details or {}
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.request_id = request_id
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for MongoDB storage"""
        return {
            "_id": self.id,
            "action": self.action,
            "user_id": self.user_id,
            "org_id": self.org_id,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "timestamp": self.timestamp,
            "details": self.details,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "request_id": self.request_id
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AuditLog':
        """Create from MongoDB dictionary"""
        id_val = data.pop("_id", None)
        return cls(id=id_val, **data)