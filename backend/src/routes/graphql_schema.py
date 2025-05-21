import typing
import strawberry
from strawberry.types import Info
from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum

from ..models.data_models import (
    ContentType as ModelContentType,
    ProcessingStatus as ModelProcessingStatus,
    SensitivityLevel as ModelSensitivityLevel,
    AccessStatus as ModelAccessStatus
)

# Enum definitions for GraphQL schema
@strawberry.enum
class ContentType(str, Enum):
    EMAIL = "email"
    DOCUMENT = "document"
    SPREADSHEET = "spreadsheet"
    PRESENTATION = "presentation"
    PDF = "pdf"
    IMAGE = "image"
    OTHER = "other"

@strawberry.enum
class ProcessingStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"

@strawberry.enum
class SensitivityLevel(str, Enum):
    GENERAL = "general"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SENSITIVE = "sensitive"

@strawberry.enum
class AccessStatus(str, Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    PENDING_REVIEW = "pending_review"

@strawberry.enum
class KeywordType(str, Enum):
    IDENTIFIER = "identifier"
    GLOBAL = "global"
    HIGH_CONFIDENCE = "high_confidence"
    GENERAL = "general"

# Type definitions
@strawberry.type
class ContentMetadata:
    content_type: str
    author: Optional[str] = None
    created_date: Optional[str] = None
    modified_date: Optional[str] = None
    title: Optional[str] = None
    subject: Optional[str] = None
    keywords: Optional[List[str]] = None
    page_count: Optional[int] = None

@strawberry.type
class EntityMatch:
    type: str
    value: str
    confidence: Optional[float] = None
    position: Optional[List[int]] = None

@strawberry.type
class YaraMatch:
    rule_id: str
    rule_name: str
    rule_description: Optional[str] = None
    strings: Optional[List[str]] = None

@strawberry.type
class LLMAnalysis:
    confidence: float
    detected_topics: List[str]
    summary: str
    recommendations: List[str]
    false_positive_probability: float

@strawberry.type
class KeywordMatch:
    category: str
    keywords: List[str]

@strawberry.type
class ContentItem:
    id: str
    title: str
    source: str
    org_id: str
    content_type: ContentType
    file_path: Optional[str] = None
    file_size: Optional[int] = None
    md5_hash: Optional[str] = None
    sha256_hash: Optional[str] = None
    created_at: str
    updated_at: str
    processing_status: ProcessingStatus
    processing_error: Optional[str] = None
    sensitivity_level: SensitivityLevel
    access_status: AccessStatus
    metadata: Optional[Dict[str, Any]] = None
    content_metadata: Optional[ContentMetadata] = None
    yara_matches: List[YaraMatch]
    keyword_matches: List[KeywordMatch]
    entity_matches: List[EntityMatch]
    llm_analysis: Optional[LLMAnalysis] = None
    embedding_id: Optional[str] = None
    related_content_ids: List[str]
    tags: List[str]
    
    @strawberry.field
    def summary(self) -> str:
        """Generate a summary of the content item."""
        if self.llm_analysis and self.llm_analysis.summary:
            return self.llm_analysis.summary
        return f"Content item: {self.title}"

@strawberry.type
class YaraRule:
    id: str
    name: str
    description: Optional[str] = None
    org_id: str
    project_id: Optional[str] = None
    rule_content: str
    instance_id: Optional[str] = None
    created_by: str
    created_at: str
    updated_at: str
    is_active: bool
    match_count: int
    false_positive_count: int
    tags: List[str]

@strawberry.type
class KeywordDictionary:
    id: str
    name: str
    description: Optional[str] = None
    org_id: str
    project_id: str
    identifier_keywords: List[str]
    global_keywords: List[str]
    high_confidence_keywords: List[str]
    general_keywords: List[str]
    created_at: str
    updated_at: str

@strawberry.type
class KeywordInstance:
    id: str
    name: str
    description: Optional[str] = None
    dictionaries: List[str]
    required_counts: Dict[str, Dict[str, int]]
    created_at: str
    updated_at: str

@strawberry.type
class User:
    id: str
    username: str
    email: str
    full_name: str
    org_id: str
    role: str
    roles: List[str]
    created_at: str
    updated_at: str
    is_active: bool
    last_login: Optional[str] = None

@strawberry.type
class Organization:
    id: str
    name: str
    display_name: str
    created_at: str
    updated_at: str
    is_active: bool
    tenant_id: Optional[str] = None

@strawberry.type
class AuditLog:
    id: str
    action: str
    user_id: str
    org_id: str
    target_type: str
    target_id: Optional[str] = None
    timestamp: str
    details: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None

@strawberry.type
class ContentProcessingResult:
    content_id: str
    status: str
    error: Optional[str] = None
    sensitivity_level: Optional[SensitivityLevel] = None
    access_status: Optional[AccessStatus] = None
    yara_matches: Optional[int] = None
    keyword_matches: Optional[Dict[str, int]] = None

@strawberry.type
class TestKeywordResult:
    analysis_id: str
    timestamp: str
    user_id: str
    text_length: int
    sensitivity_level: SensitivityLevel
    access_granted: bool
    action_required: str
    category_analysis: Dict[str, Any]
    recommendations: List[str]

@strawberry.type
class MilvusSearchResult:
    content_id: str
    title: str
    similarity: float
    snippet: str
    sensitivity_level: SensitivityLevel

@strawberry.type
class PaginatedContentItems:
    items: List[ContentItem]
    total: int
    page: int
    pages: int

@strawberry.type
class PaginatedYaraRules:
    items: List[YaraRule]
    total: int
    page: int
    pages: int

@strawberry.type
class PaginatedKeywordDictionaries:
    items: List[KeywordDictionary]
    total: int
    page: int
    pages: int

@strawberry.type
class PaginatedAuditLogs:
    items: List[AuditLog]
    total: int
    page: int
    pages: int

# Input types for mutations
@strawberry.input
class ContentItemInput:
    title: str
    source: str
    org_id: str
    content_type: ContentType
    file_path: Optional[str] = None
    raw_content: Optional[str] = None
    tags: List[str] = strawberry.field(default_factory=list)

@strawberry.input
class YaraRuleInput:
    name: str
    description: Optional[str] = None
    org_id: str
    project_id: Optional[str] = None
    rule_content: str
    instance_id: Optional[str] = None
    is_active: bool = True
    tags: List[str] = strawberry.field(default_factory=list)

@strawberry.input
class KeywordDictionaryInput:
    name: str
    description: Optional[str] = None
    org_id: str
    project_id: str
    identifier_keywords: List[str] = strawberry.field(default_factory=list)
    global_keywords: List[str] = strawberry.field(default_factory=list)
    high_confidence_keywords: List[str] = strawberry.field(default_factory=list)
    general_keywords: List[str] = strawberry.field(default_factory=list)

@strawberry.input
class KeywordInstanceInput:
    name: str
    description: Optional[str] = None
    dictionaries: List[str]
    required_counts: Optional[Dict[str, Dict[str, int]]] = None

@strawberry.input
class TestKeywordInput:
    text: str
    user_id: str
    user_roles: List[str] = strawberry.field(default_factory=lambda: ["employee"])
    context: Optional[str] = None

# Query type
@strawberry.type
class Query:
    @strawberry.field
    def content_item(self, info: Info, id: str) -> Optional[ContentItem]:
        """Get a content item by ID."""
        # This would be implemented with actual database logic
        content_service = info.context["content_service"]
        return content_service.get_content_item(id)
    
    @strawberry.field
    def content_items(self, 
                    info: Info, 
                    org_id: str, 
                    page: int = 1, 
                    limit: int = 20,
                    content_type: Optional[ContentType] = None,
                    sensitivity_level: Optional[SensitivityLevel] = None,
                    search: Optional[str] = None) -> PaginatedContentItems:
        """Get paginated content items with filtering."""
        content_service = info.context["content_service"]
        return content_service.get_content_items(
            org_id=org_id,
            page=page,
            limit=limit,
            content_type=content_type,
            sensitivity_level=sensitivity_level,
            search=search
        )
    
    @strawberry.field
    def yara_rule(self, info: Info, id: str) -> Optional[YaraRule]:
        """Get a YARA rule by ID."""
        rule_service = info.context["rule_service"]
        return rule_service.get_yara_rule(id)
    
    @strawberry.field
    def yara_rules(self,
                 info: Info,
                 org_id: str,
                 page: int = 1,
                 limit: int = 20,
                 is_active: Optional[bool] = None,
                 search: Optional[str] = None) -> PaginatedYaraRules:
        """Get paginated YARA rules with filtering."""
        rule_service = info.context["rule_service"]
        return rule_service.get_yara_rules(
            org_id=org_id,
            page=page,
            limit=limit,
            is_active=is_active,
            search=search
        )
    
    @strawberry.field
    def keyword_dictionary(self, info: Info, id: str) -> Optional[KeywordDictionary]:
        """Get a keyword dictionary by ID."""
        keyword_service = info.context["keyword_service"]
        return keyword_service.get_keyword_dictionary(id)
    
    @strawberry.field
    def keyword_dictionaries(self,
                          info: Info,
                          org_id: str,
                          page: int = 1,
                          limit: int = 20,
                          project_id: Optional[str] = None,
                          search: Optional[str] = None) -> PaginatedKeywordDictionaries:
        """Get paginated keyword dictionaries with filtering."""
        keyword_service = info.context["keyword_service"]
        return keyword_service.get_keyword_dictionaries(
            org_id=org_id,
            page=page,
            limit=limit,
            project_id=project_id,
            search=search
        )
    
    @strawberry.field
    def keyword_instance(self, info: Info, id: str) -> Optional[KeywordInstance]:
        """Get a keyword instance by ID."""
        keyword_service = info.context["keyword_service"]
        return keyword_service.get_keyword_instance(id)
    
    @strawberry.field
    def search_similar_content(self,
                             info: Info,
                             text: str,
                             org_id: str,
                             limit: int = 10) -> List[MilvusSearchResult]:
        """Search for similar content using vector embeddings."""
        search_service = info.context["search_service"]
        return search_service.search_similar_content(
            text=text,
            org_id=org_id,
            limit=limit
        )
    
    @strawberry.field
    def audit_logs(self,
                 info: Info,
                 org_id: str,
                 page: int = 1,
                 limit: int = 20,
                 user_id: Optional[str] = None,
                 action: Optional[str] = None,
                 target_type: Optional[str] = None,
                 from_date: Optional[str] = None,
                 to_date: Optional[str] = None) -> PaginatedAuditLogs:
        """Get paginated audit logs with filtering."""
        audit_service = info.context["audit_service"]
        return audit_service.get_audit_logs(
            org_id=org_id,
            page=page,
            limit=limit,
            user_id=user_id,
            action=action,
            target_type=target_type,
            from_date=from_date,
            to_date=to_date
        )
    
    @strawberry.field
    def user(self, info: Info, id: str) -> Optional[User]:
        """Get a user by ID."""
        user_service = info.context["user_service"]
        return user_service.get_user(id)
    
    @strawberry.field
    def users(self, info: Info, org_id: str) -> List[User]:
        """Get users for an organization."""
        user_service = info.context["user_service"]
        return user_service.get_users(org_id)
    
    @strawberry.field
    def organization(self, info: Info, id: str) -> Optional[Organization]:
        """Get an organization by ID."""
        org_service = info.context["org_service"]
        return org_service.get_organization(id)

# Mutation type
@strawberry.type
class Mutation:
    @strawberry.mutation
    def process_content(self, info: Info, input: ContentItemInput) -> ContentProcessingResult:
        """Process content and analyze it."""
        content_service = info.context["content_service"]
        return content_service.process_content(input)
    
    @strawberry.mutation
    def create_yara_rule(self, info: Info, input: YaraRuleInput) -> YaraRule:
        """Create a new YARA rule."""
        rule_service = info.context["rule_service"]
        return rule_service.create_yara_rule(input)
    
    @strawberry.mutation
    def update_yara_rule(self, info: Info, id: str, input: YaraRuleInput) -> YaraRule:
        """Update an existing YARA rule."""
        rule_service = info.context["rule_service"]
        return rule_service.update_yara_rule(id, input)
    
    @strawberry.mutation
    def delete_yara_rule(self, info: Info, id: str) -> bool:
        """Delete a YARA rule."""
        rule_service = info.context["rule_service"]
        return rule_service.delete_yara_rule(id)
    
    @strawberry.mutation
    def create_keyword_dictionary(self, info: Info, input: KeywordDictionaryInput) -> KeywordDictionary:
        """Create a new keyword dictionary."""
        keyword_service = info.context["keyword_service"]
        return keyword_service.create_keyword_dictionary(input)
    
    @strawberry.mutation
    def update_keyword_dictionary(self, info: Info, id: str, input: KeywordDictionaryInput) -> KeywordDictionary:
        """Update an existing keyword dictionary."""
        keyword_service = info.context["keyword_service"]
        return keyword_service.update_keyword_dictionary(id, input)
    
    @strawberry.mutation
    def delete_keyword_dictionary(self, info: Info, id: str) -> bool:
        """Delete a keyword dictionary."""
        keyword_service = info.context["keyword_service"]
        return keyword_service.delete_keyword_dictionary(id)
    
    @strawberry.mutation
    def create_keyword_instance(self, info: Info, input: KeywordInstanceInput) -> KeywordInstance:
        """Create a new keyword instance."""
        keyword_service = info.context["keyword_service"]
        return keyword_service.create_keyword_instance(input)
    
    @strawberry.mutation
    def update_keyword_instance(self, info: Info, id: str, input: KeywordInstanceInput) -> KeywordInstance:
        """Update an existing keyword instance."""
        keyword_service = info.context["keyword_service"]
        return keyword_service.update_keyword_instance(id, input)
    
    @strawberry.mutation
    def delete_keyword_instance(self, info: Info, id: str) -> bool:
        """Delete a keyword instance."""
        keyword_service = info.context["keyword_service"]
        return keyword_service.delete_keyword_instance(id)
    
    @strawberry.mutation
    def generate_rule_from_keywords(self, 
                                  info: Info, 
                                  instance_id: str, 
                                  rule_name: str,
                                  description: Optional[str] = None) -> YaraRule:
        """Generate a YARA rule from a keyword instance."""
        rule_service = info.context["rule_service"]
        return rule_service.generate_rule_from_keywords(
            instance_id=instance_id,
            rule_name=rule_name,
            description=description
        )
    
    @strawberry.mutation
    def test_keyword_rule(self, info: Info, input: TestKeywordInput) -> TestKeywordResult:
        """Test a keyword rule on sample text."""
        keyword_service = info.context["keyword_service"]
        return keyword_service.test_keyword_rule(input)
    
    @strawberry.mutation
    def mark_false_positive(self, info: Info, content_id: str, rule_id: str) -> bool:
        """Mark a rule match as a false positive."""
        rule_service = info.context["rule_service"]
        return rule_service.mark_false_positive(
            content_id=content_id,
            rule_id=rule_id
        )

# Create schema
schema = strawberry.Schema(query=Query, mutation=Mutation)