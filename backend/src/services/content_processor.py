import logging
import os
import hashlib
import requests
import json
import time
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import uuid

from ..models.data_models import ContentItem, ContentType, ProcessingStatus, SensitivityLevel, AccessStatus
from ..integrations.yara.yara_engine import YaraXEngine
from ..services.keyword_manager import KeywordManager

class ContentProcessor:
    """
    Handles processing of content through the analysis pipeline:
    1. Parse content using Apache Tika
    2. Extract metadata
    3. Clean and tokenize content
    4. Apply YARA-X rules
    5. Process through NLP pipeline
    6. Analyze with LLM
    7. Determine sensitivity and access permissions
    """
    
    def __init__(self, 
                db_connection,  
                yara_engine: YaraXEngine = None,
                keyword_manager: KeywordManager = None,
                tika_server: str = "http://127.0.0.1:9998",
                llm_service_url: Optional[str] = None):
        """
        Initialize content processor.
        
        Args:
            db_connection: MongoDB connection
            yara_engine: YaraXEngine instance
            keyword_manager: KeywordManager instance
            tika_server: URL of Apache Tika server
            llm_service_url: URL of LLM service for contextual analysis
        """
        self.logger = logging.getLogger(__name__)
        self.db = db_connection
        
        # Initialize components
        self.yara_engine = yara_engine or YaraXEngine()
        self.keyword_manager = keyword_manager or KeywordManager()
        self.tika_server = tika_server
        self.llm_service_url = llm_service_url
        
        # Get MongoDB collections
        self.content_collection = self.db.get_collection("content")
        self.rules_collection = self.db.get_collection("yara_rules")
        self.audit_collection = self.db.get_collection("audit_logs")
    
    def process_file(self, 
                   file_path: str, 
                   org_id: str,
                   title: Optional[str] = None,
                   source: str = "file_upload",
                   user_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Process a file through the complete pipeline.
        
        Args:
            file_path: Path to the file
            org_id: Organization ID
            title: Optional title (defaults to filename)
            source: Source of the content
            user_id: User who uploaded/processed the file
            
        Returns:
            Processing result with content item ID
        """
        # Check if file exists
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Start by creating a content item
        content_item = self._create_content_item(file_path, org_id, title, source)
        
        try:
            # Update processing status
            content_item.processing_status = ProcessingStatus.PROCESSING
            self._save_content_item(content_item)
            
            # Process content through pipeline
            self._process_content_pipeline(content_item, user_id)
            
            # Update final status
            content_item.processing_status = ProcessingStatus.COMPLETED
            content_item.updated_at = datetime.now()
            self._save_content_item(content_item)
            
            return {
                "content_id": content_item.id,
                "status": "completed",
                "sensitivity_level": content_item.sensitivity_level,
                "access_status": content_item.access_status,
                "yara_matches": len(content_item.yara_matches),
                "keyword_matches": {
                    category: len(matches) 
                    for category, matches in content_item.keyword_matches.items()
                }
            }
            
        except Exception as e:
            # Handle processing error
            self.logger.error(f"Error processing file {file_path}: {str(e)}")
            
            # Update content item with error
            content_item.processing_status = ProcessingStatus.FAILED
            content_item.processing_error = str(e)
            content_item.updated_at = datetime.now()
            self._save_content_item(content_item)
            
            return {
                "content_id": content_item.id,
                "status": "failed",
                "error": str(e)
            }
    
    def process_text(self,
                   text: str,
                   org_id: str,
                   title: str,
                   content_type: ContentType = ContentType.OTHER,
                   source: str = "direct_input",
                   user_id: Optional[str] = None,
                   metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Process raw text through the pipeline.
        
        Args:
            text: Raw text content
            org_id: Organization ID
            title: Title for the content
            content_type: Type of content
            source: Source of the content
            user_id: User who provided the content
            metadata: Additional metadata
            
        Returns:
            Processing result with content item ID
        """
        # Create a content item for the text
        content_id = str(uuid.uuid4())
        content_item = ContentItem(
            id=content_id,
            title=title,
            source=source,
            org_id=org_id,
            content_type=content_type,
            raw_content=text,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            processing_status=ProcessingStatus.PROCESSING,
            metadata=metadata or {}
        )
        
        # Save initial content item
        self._save_content_item(content_item)
        
        try:
            # Since we already have the text, just clean it
            content_item.clean_content = self._clean_text(text)
            
            # Process through remaining pipeline
            self._process_content_pipeline(content_item, user_id, skip_parsing=True)
            
            # Update final status
            content_item.processing_status = ProcessingStatus.COMPLETED
            content_item.updated_at = datetime.now()
            self._save_content_item(content_item)
            
            return {
                "content_id": content_item.id,
                "status": "completed",
                "sensitivity_level": content_item.sensitivity_level,
                "access_status": content_item.access_status,
                "yara_matches": len(content_item.yara_matches),
                "keyword_matches": {
                    category: len(matches) 
                    for category, matches in content_item.keyword_matches.items()
                }
            }
            
        except Exception as e:
            # Handle processing error
            self.logger.error(f"Error processing text content: {str(e)}")
            
            # Update content item with error
            content_item.processing_status = ProcessingStatus.FAILED
            content_item.processing_error = str(e)
            content_item.updated_at = datetime.now()
            self._save_content_item(content_item)
            
            return {
                "content_id": content_item.id,
                "status": "failed",
                "error": str(e)
            }
    
    def _create_content_item(self, 
                           file_path: str, 
                           org_id: str,
                           title: Optional[str] = None,
                           source: str = "file_upload") -> ContentItem:
        """
        Create a new content item for a file.
        
        Args:
            file_path: Path to the file
            org_id: Organization ID
            title: Optional title (defaults to filename)
            source: Source of the content
            
        Returns:
            New ContentItem object
        """
        # Generate content ID
        content_id = str(uuid.uuid4())
        
        # Get file information
        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)
        
        # If title not provided, use filename
        if not title:
            title = file_name
        
        # Determine content type from file extension
        content_type = self._determine_content_type(file_path)
        
        # Calculate file hashes
        md5_hash, sha256_hash = self._calculate_file_hashes(file_path)
        
        # Create content item
        content_item = ContentItem(
            id=content_id,
            title=title,
            source=source,
            org_id=org_id,
            content_type=content_type,
            file_path=file_path,
            file_size=file_size,
            md5_hash=md5_hash,
            sha256_hash=sha256_hash,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            processing_status=ProcessingStatus.PENDING,
            metadata={
                "original_filename": file_name
            }
        )
        
        # Save to database
        self._save_content_item(content_item)
        
        return content_item
    
    def _save_content_item(self, content_item: ContentItem):
        """Save a content item to the database."""
        self.content_collection.replace_one(
            {"_id": content_item.id},
            content_item.to_dict(),
            upsert=True
        )
    
    def _determine_content_type(self, file_path: str) -> ContentType:
        """Determine content type from file extension."""
        ext = os.path.splitext(file_path)[1].lower()
        
        # Map extensions to content types
        ext_map = {
            '.pdf': ContentType.PDF,
            '.doc': ContentType.DOCUMENT,
            '.docx': ContentType.DOCUMENT,
            '.xls': ContentType.SPREADSHEET,
            '.xlsx': ContentType.SPREADSHEET,
            '.ppt': ContentType.PRESENTATION,
            '.pptx': ContentType.PRESENTATION,
            '.txt': ContentType.DOCUMENT,
            '.eml': ContentType.EMAIL,
            '.msg': ContentType.EMAIL,
            '.jpg': ContentType.IMAGE,
            '.jpeg': ContentType.IMAGE,
            '.png': ContentType.IMAGE,
            '.gif': ContentType.IMAGE
        }
        
        return ext_map.get(ext, ContentType.OTHER)
    
    def _calculate_file_hashes(self, file_path: str) -> Tuple[str, str]:
        """Calculate MD5 and SHA256 hashes for a file."""
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            # Read and update in chunks to handle large files
            for chunk in iter(lambda: f.read(4096), b''):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
        
        return md5_hash.hexdigest(), sha256_hash.hexdigest()
    
    def _process_content_pipeline(self, 
                               content_item: ContentItem,
                               user_id: Optional[str] = None,
                               skip_parsing: bool = False):
        """
        Process a content item through the complete pipeline.
        
        Args:
            content_item: ContentItem to process
            user_id: User processing the content
            skip_parsing: Whether to skip the parsing step (for raw text)
        """
        if not skip_parsing:
            # Step 1: Parse with Apache Tika
            content_text, metadata = self._parse_with_tika(content_item.file_path)
            content_item.raw_content = content_text
            content_item.content_metadata = metadata
            self._save_content_item(content_item)
        else:
            content_text = content_item.raw_content
        
        # Step 2: Clean and process text
        if not content_item.clean_content:
            content_item.clean_content = self._clean_text(content_text)
            self._save_content_item(content_item)
        
        # Step 3: Apply YARA-X rules
        yara_matches = self._apply_yara_rules(content_item.clean_content, content_item.org_id)
        content_item.yara_matches = yara_matches
        self._save_content_item(content_item)
        
        # Step 4: Extract keyword matches
        keyword_matches = self._extract_keyword_matches(content_item.clean_content, content_item.org_id)
        content_item.keyword_matches = keyword_matches
        self._save_content_item(content_item)
        
        # Step 5: Extract entities (NLP)
        entity_matches = self._extract_entities(content_item.clean_content)
        content_item.entity_matches = entity_matches
        self._save_content_item(content_item)
        
        # Step 6: LLM analysis
        llm_analysis = self._analyze_with_llm(content_item.clean_content, yara_matches, keyword_matches)
        content_item.llm_analysis = llm_analysis
        self._save_content_item(content_item)
        
        # Step 7: Determine sensitivity level and access status
        sensitivity_level, access_status = self._determine_sensitivity(
            yara_matches, 
            keyword_matches, 
            llm_analysis
        )
        content_item.sensitivity_level = sensitivity_level
        content_item.access_status = access_status
        
        # Step 8: Generate embeddings ID (placeholder)
        content_item.embedding_id = f"emb_{content_item.id}"
        
        # Log audit record
        if user_id:
            self._log_content_audit(content_item, user_id)
    
    def _parse_with_tika(self, file_path: str) -> Tuple[str, Dict[str, Any]]:
        """
        Parse a file using Apache Tika.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Tuple of (extracted_text, metadata)
        """
        try:
            # Check if Tika server is available
            tika_status = requests.get(f"{self.tika_server}/tika", timeout=5)
            if tika_status.status_code != 200:
                raise ConnectionError(f"Tika server not available at {self.tika_server}")
            
            # Send file for parsing
            with open(file_path, 'rb') as f:
                response = requests.put(
                    f"{self.tika_server}/tika",
                    data=f,
                    headers={
                        'Accept': 'text/plain, application/json'
                    }
                )
            
            if response.status_code != 200:
                raise ValueError(f"Tika parsing failed with status {response.status_code}: {response.text}")
            
            # Extract text content
            text_content = response.text
            
            # Get metadata separately
            with open(file_path, 'rb') as f:
                meta_response = requests.put(
                    f"{self.tika_server}/meta",
                    data=f,
                    headers={
                        'Accept': 'application/json'
                    }
                )
            
            metadata = meta_response.json() if meta_response.status_code == 200 else {}
            
            return text_content, metadata
            
        except Exception as e:
            self.logger.error(f"Error parsing file with Tika: {str(e)}")
            raise
    
    def _clean_text(self, text: str) -> str:
        """
        Clean and normalize text content.
        
        Args:
            text: Raw text content
            
        Returns:
            Cleaned text
        """
        if not text:
            return ""
        
        # Simple cleaning operations (would be more advanced in production)
        cleaned = text.strip()
        
        # Remove excessive whitespace
        cleaned = " ".join(cleaned.split())
        
        return cleaned
    
    def _apply_yara_rules(self, content: str, org_id: str) -> List[Dict[str, Any]]:
        """
        Apply YARA-X rules to content.
        
        Args:
            content: Cleaned content text
            org_id: Organization ID to filter rules
            
        Returns:
            List of rule match results
        """
        # Get active rules for this organization
        rules_cursor = self.rules_collection.find({
            "org_id": org_id,
            "is_active": True
        })
        
        all_matches = []
        
        # Apply each rule
        for rule in rules_cursor:
            # Check if rule has compiled path
            if rule.get("compiled_path") and os.path.exists(rule["compiled_path"]):
                # Use compiled rule
                matches = self.yara_engine.scan_content(
                    content,
                    compiled_rules=rule["compiled_path"]
                )
            else:
                # Compile and use rule content
                matches = self.yara_engine.scan_content(
                    content,
                    rules_content=rule["rule_content"]
                )
            
            # Add rule metadata to matches
            for match in matches:
                match["rule_id"] = rule["_id"]
                match["rule_name"] = rule["name"]
                match["rule_description"] = rule.get("description", "")
                
                # Add to all matches
                all_matches.append(match)
            
            # Update match count if matches found
            if matches:
                self.rules_collection.update_one(
                    {"_id": rule["_id"]},
                    {"$inc": {"match_count": 1}}
                )
        
        return all_matches
    
    def _extract_keyword_matches(self, content: str, org_id: str) -> Dict[str, List[str]]:
        """
        Extract keyword matches from content.
        
        Args:
            content: Cleaned content text
            org_id: Organization ID
            
        Returns:
            Dictionary of keyword matches by category
        """
        # Convert content to lowercase for case-insensitive matching
        content_lower = content.lower()
        
        # Get all keyword dictionaries for this organization
        # In a real implementation, this would be more efficient
        # For now, we'll use a simple approach
        
        result = {
            "identifier": [],
            "global": [],
            "high_confidence": [],
            "general": []
        }
        
        # For each keyword category, check for matches
        for category in result:
            # Get keywords for this category
            # This is a placeholder for the actual implementation
            keywords = self._get_org_keywords(org_id, category)
            
            # Check for matches
            for keyword in keywords:
                if keyword.lower() in content_lower:
                    result[category].append(keyword)
        
        return result
    
    def _get_org_keywords(self, org_id: str, category: str) -> List[str]:
        """
        Get keywords for an organization and category.
        This is a placeholder implementation.
        
        Args:
            org_id: Organization ID
            category: Keyword category
            
        Returns:
            List of keywords
        """
        # In a real implementation, this would fetch from the database
        # For now, return placeholder keywords
        placeholder_keywords = {
            "identifier": [
                "classified", "confidential", "secret", "top secret", "restricted",
                "internal only", "proprietary", "privileged", "sensitive",
                "ssn", "social security", "tax id", "employee id", "patient id"
            ],
            "global": [
                "project", "initiative", "strategy", "roadmap", "forecast",
                "competitor", "acquisition", "merger", "revenue", "profit",
                "loss", "budget", "investment", "partnership", "alliance"
            ],
            "high_confidence": [
                "breach", "leak", "unauthorized", "violation", "non-compliance",
                "expose", "disclosure", "compromise", "vulnerability", "incident",
                "privacy violation", "data loss", "security incident"
            ],
            "general": [
                "personal", "private", "financial", "medical", "health",
                "insurance", "legal", "contract", "agreement", "settlement",
                "investment", "salary", "compensation", "bonus", "performance"
            ]
        }
        
        return placeholder_keywords.get(category, [])
    
    def _extract_entities(self, content: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Extract entities from content using NLP.
        This is a placeholder implementation.
        
        Args:
            content: Cleaned content text
            
        Returns:
            Dictionary of entities by type
        """
        # In a real implementation, this would use spaCy or similar
        # For now, return placeholder entities
        
        # Simple pattern matching for demonstration
        entities = {
            "person": [],
            "organization": [],
            "location": [],
            "date": [],
            "money": []
        }
        
        # Example: Find potential SSNs with simple regex
        import re
        ssn_pattern = r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b'
        ssn_matches = re.findall(ssn_pattern, content)
        
        if ssn_matches:
            entities["ssn"] = [{"value": ssn} for ssn in ssn_matches]
        
        return entities
    
    def _analyze_with_llm(self, 
                       content: str, 
                       yara_matches: List[Dict[str, Any]],
                       keyword_matches: Dict[str, List[str]]) -> Dict[str, Any]:
        """
        Analyze content with LLM to determine context and sensitivity.
        This is a placeholder implementation.
        
        Args:
            content: Cleaned content text
            yara_matches: YARA rule matches
            keyword_matches: Keyword matches by category
            
        Returns:
            LLM analysis results
        """
        # In a real implementation, this would call an LLM service
        # For now, return placeholder analysis
        
        # Count total matches
        total_yara_matches = len(yara_matches)
        total_keyword_matches = sum(len(matches) for category, matches in keyword_matches.items())
        
        # Simple sensitivity calculation based on matches
        confidence = 0.0
        if total_yara_matches > 0 or total_keyword_matches > 0:
            # Calculate confidence based on matches
            yara_weight = 0.6
            keyword_weight = 0.4
            
            max_yara = 5  # Normalize to max 5 YARA matches
            max_keywords = 20  # Normalize to max 20 keyword matches
            
            yara_score = min(total_yara_matches / max_yara, 1.0)
            keyword_score = min(total_keyword_matches / max_keywords, 1.0)
            
            confidence = (yara_weight * yara_score) + (keyword_weight * keyword_score)
        
        # Generate sample topics
        sample_topics = ["business", "strategy", "financial", "personnel"]
        if "confidential" in keyword_matches.get("identifier", []):
            sample_topics.append("confidential information")
        if "breach" in keyword_matches.get("high_confidence", []):
            sample_topics.append("security incident")
        
        # Generate analysis result
        return {
            "timestamp": datetime.now().isoformat(),
            "confidence": confidence,
            "detected_topics": sample_topics,
            "summary": "This is a placeholder LLM analysis summary.",
            "recommendations": [
                "Review document classification",
                "Check for sensitive information"
            ],
            "false_positive_probability": 1.0 - confidence
        }
    
    def _determine_sensitivity(self, 
                             yara_matches: List[Dict[str, Any]],
                             keyword_matches: Dict[str, List[str]],
                             llm_analysis: Dict[str, Any]) -> Tuple[SensitivityLevel, AccessStatus]:
        """
        Determine content sensitivity level and access status.
        
        Args:
            yara_matches: YARA rule matches
            keyword_matches: Keyword matches by category
            llm_analysis: LLM analysis results
            
        Returns:
            Tuple of (sensitivity_level, access_status)
        """
        # Check if there are YARA matches
        has_yara_matches = len(yara_matches) > 0
        
        # Check keyword matches by category
        identifier_matches = len(keyword_matches.get("identifier", []))
        high_confidence_matches = len(keyword_matches.get("high_confidence", []))
        global_matches = len(keyword_matches.get("global", []))
        general_matches = len(keyword_matches.get("general", []))
        
        # Get LLM confidence score
        llm_confidence = llm_analysis.get("confidence", 0.0)
        
        # Determine sensitivity level
        sensitivity_level = SensitivityLevel.GENERAL
        
        if (identifier_matches > 0 and high_confidence_matches > 0) or has_yara_matches:
            sensitivity_level = SensitivityLevel.SENSITIVE
        elif identifier_matches > 0 or high_confidence_matches > 0:
            sensitivity_level = SensitivityLevel.CONFIDENTIAL
        elif global_matches > 0 or general_matches > 2:
            sensitivity_level = SensitivityLevel.INTERNAL
        
        # Adjust based on LLM confidence
        if llm_confidence > 0.8 and sensitivity_level != SensitivityLevel.SENSITIVE:
            sensitivity_level = SensitivityLevel.CONFIDENTIAL
        
        # Determine access status
        # By default, allow access
        access_status = AccessStatus.ALLOWED
        
        # If sensitive, block access by default
        if sensitivity_level == SensitivityLevel.SENSITIVE:
            access_status = AccessStatus.BLOCKED
        
        # If confidential, require review
        elif sensitivity_level == SensitivityLevel.CONFIDENTIAL:
            access_status = AccessStatus.PENDING_REVIEW
        
        return sensitivity_level, access_status
    
    def _log_content_audit(self, content_item: ContentItem, user_id: str):
        """
        Log an audit record for content processing.
        
        Args:
            content_item: Processed content item
            user_id: User who processed the content
        """
        audit_id = str(uuid.uuid4())
        
        audit_record = {
            "_id": audit_id,
            "action": "content_processed",
            "user_id": user_id,
            "org_id": content_item.org_id,
            "target_type": "content",
            "target_id": content_item.id,
            "timestamp": datetime.now(),
            "details": {
                "content_title": content_item.title,
                "content_type": content_item.content_type,
                "sensitivity_level": content_item.sensitivity_level,
                "access_status": content_item.access_status,
                "yara_matches": len(content_item.yara_matches),
                "keyword_matches": {
                    category: len(matches) 
                    for category, matches in content_item.keyword_matches.items()
                }
            }
        }
        
        self.audit_collection.insert_one(audit_record)