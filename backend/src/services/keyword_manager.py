import json
import logging
import os
from typing import Dict, List, Any, Optional, Set, Tuple
from enum import Enum

class KeywordType(str, Enum):
    IDENTIFIER = "identifier"
    GLOBAL = "global"
    HIGH_CONFIDENCE = "high_confidence"
    GENERAL = "general"

class KeywordManager:
    """
    Manages keyword dictionaries for the CIPHER CRYPT system.
    Handles:
    - Organization of keywords into dictionaries by type
    - Grouping of dictionaries into rule instances
    - Persistence and retrieval of dictionaries
    """
    
    def __init__(self, storage_dir: str = None):
        """
        Initialize the keyword manager with a storage directory.
        
        Args:
            storage_dir: Directory to store keyword dictionaries
        """
        self.logger = logging.getLogger(__name__)
        
        # Default storage directory if not provided
        if not storage_dir:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            self.storage_dir = os.path.join(base_dir, "data", "keywords")
        else:
            self.storage_dir = storage_dir
            
        # Create storage directory if it doesn't exist
        os.makedirs(self.storage_dir, exist_ok=True)
        
        # Dictionary to hold keyword dictionaries by organization/project
        self.dictionaries = {}
        self.instances = {}
        
        # Load existing dictionaries
        self._load_dictionaries()
        self._load_instances()
    
    def _load_dictionaries(self):
        """Load existing keyword dictionaries from storage."""
        dict_dir = os.path.join(self.storage_dir, "dictionaries")
        if not os.path.exists(dict_dir):
            os.makedirs(dict_dir, exist_ok=True)
            return
            
        for filename in os.listdir(dict_dir):
            if filename.endswith(".json"):
                try:
                    dict_path = os.path.join(dict_dir, filename)
                    with open(dict_path, 'r') as f:
                        dictionary = json.load(f)
                    
                    dict_id = os.path.splitext(filename)[0]  # Remove .json
                    self.dictionaries[dict_id] = dictionary
                    self.logger.info(f"Loaded dictionary: {dict_id}")
                except Exception as e:
                    self.logger.error(f"Failed to load dictionary {filename}: {e}")
    
    def _load_instances(self):
        """Load existing rule instances from storage."""
        inst_dir = os.path.join(self.storage_dir, "instances")
        if not os.path.exists(inst_dir):
            os.makedirs(inst_dir, exist_ok=True)
            return
            
        for filename in os.listdir(inst_dir):
            if filename.endswith(".json"):
                try:
                    inst_path = os.path.join(inst_dir, filename)
                    with open(inst_path, 'r') as f:
                        instance = json.load(f)
                    
                    inst_id = os.path.splitext(filename)[0]  # Remove .json
                    self.instances[inst_id] = instance
                    self.logger.info(f"Loaded instance: {inst_id}")
                except Exception as e:
                    self.logger.error(f"Failed to load instance {filename}: {e}")
    
    def create_dictionary(self, 
                         dict_id: str, 
                         org_id: str,
                         project_id: str,
                         name: str,
                         description: str,
                         identifier_keywords: List[str] = None,
                         global_keywords: List[str] = None,
                         high_confidence_keywords: List[str] = None,
                         general_keywords: List[str] = None) -> Dict[str, Any]:
        """
        Create a new keyword dictionary.
        
        Args:
            dict_id: Unique identifier for the dictionary
            org_id: Organization ID this dictionary belongs to
            project_id: Project ID this dictionary belongs to
            name: Human-readable name for the dictionary
            description: Description of the dictionary's purpose
            identifier_keywords: List of identifier keywords
            global_keywords: List of global keywords
            high_confidence_keywords: List of high confidence keywords
            general_keywords: List of general keywords
            
        Returns:
            The created dictionary object
        """
        # Initialize empty lists if not provided
        identifier_keywords = identifier_keywords or []
        global_keywords = global_keywords or []
        high_confidence_keywords = high_confidence_keywords or []
        general_keywords = general_keywords or []
        
        # Create dictionary object
        dictionary = {
            "id": dict_id,
            "org_id": org_id,
            "project_id": project_id,
            "name": name,
            "description": description,
            "keywords": {
                KeywordType.IDENTIFIER: identifier_keywords,
                KeywordType.GLOBAL: global_keywords,
                KeywordType.HIGH_CONFIDENCE: high_confidence_keywords,
                KeywordType.GENERAL: general_keywords
            },
            "metadata": {
                "created_at": None,  # Would be set by database
                "updated_at": None,
                "keyword_counts": {
                    KeywordType.IDENTIFIER: len(identifier_keywords),
                    KeywordType.GLOBAL: len(global_keywords),
                    KeywordType.HIGH_CONFIDENCE: len(high_confidence_keywords),
                    KeywordType.GENERAL: len(general_keywords)
                }
            }
        }
        
        # Save to memory
        self.dictionaries[dict_id] = dictionary
        
        # Save to storage
        self._save_dictionary(dict_id, dictionary)
        
        return dictionary
    
    def _save_dictionary(self, dict_id: str, dictionary: Dict[str, Any]):
        """Save a dictionary to storage."""
        dict_dir = os.path.join(self.storage_dir, "dictionaries")
        os.makedirs(dict_dir, exist_ok=True)
        
        dict_path = os.path.join(dict_dir, f"{dict_id}.json")
        with open(dict_path, 'w') as f:
            json.dump(dictionary, f, indent=2)
        
        self.logger.info(f"Saved dictionary: {dict_id}")
    
    def get_dictionary(self, dict_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a dictionary by ID.
        
        Args:
            dict_id: ID of the dictionary to retrieve
            
        Returns:
            Dictionary object or None if not found
        """
        return self.dictionaries.get(dict_id)
    
    def update_dictionary(self, 
                         dict_id: str,
                         updates: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update a dictionary with new values.
        
        Args:
            dict_id: ID of the dictionary to update
            updates: Dictionary of values to update
            
        Returns:
            Updated dictionary object
        """
        if dict_id not in self.dictionaries:
            raise ValueError(f"Dictionary {dict_id} not found")
        
        dictionary = self.dictionaries[dict_id]
        
        # Update simple fields
        for field in ["name", "description", "org_id", "project_id"]:
            if field in updates:
                dictionary[field] = updates[field]
        
        # Update keywords if provided
        if "keywords" in updates:
            for kw_type, keywords in updates["keywords"].items():
                if kw_type in dictionary["keywords"]:
                    dictionary["keywords"][kw_type] = keywords
                    dictionary["metadata"]["keyword_counts"][kw_type] = len(keywords)
        
        # Save updated dictionary
        self._save_dictionary(dict_id, dictionary)
        
        return dictionary
    
    def delete_dictionary(self, dict_id: str) -> bool:
        """
        Delete a dictionary.
        
        Args:
            dict_id: ID of the dictionary to delete
            
        Returns:
            True if deleted, False if not found
        """
        if dict_id not in self.dictionaries:
            return False
        
        # Remove from memory
        del self.dictionaries[dict_id]
        
        # Remove from storage
        dict_path = os.path.join(self.storage_dir, "dictionaries", f"{dict_id}.json")
        if os.path.exists(dict_path):
            os.remove(dict_path)
            self.logger.info(f"Deleted dictionary: {dict_id}")
        
        return True
    
    def add_keywords(self, 
                    dict_id: str,
                    keyword_type: KeywordType,
                    keywords: List[str]) -> Dict[str, Any]:
        """
        Add keywords to a dictionary.
        
        Args:
            dict_id: ID of the dictionary to add to
            keyword_type: Type of keywords to add
            keywords: List of keywords to add
            
        Returns:
            Updated dictionary object
        """
        if dict_id not in self.dictionaries:
            raise ValueError(f"Dictionary {dict_id} not found")
        
        dictionary = self.dictionaries[dict_id]
        
        # Add keywords, avoiding duplicates
        existing = set(dictionary["keywords"].get(keyword_type, []))
        new_keywords = existing.union(set(keywords))
        dictionary["keywords"][keyword_type] = list(new_keywords)
        
        # Update counts
        dictionary["metadata"]["keyword_counts"][keyword_type] = len(new_keywords)
        
        # Save updated dictionary
        self._save_dictionary(dict_id, dictionary)
        
        return dictionary
    
    def remove_keywords(self,
                       dict_id: str,
                       keyword_type: KeywordType,
                       keywords: List[str]) -> Dict[str, Any]:
        """
        Remove keywords from a dictionary.
        
        Args:
            dict_id: ID of the dictionary to remove from
            keyword_type: Type of keywords to remove
            keywords: List of keywords to remove
            
        Returns:
            Updated dictionary object
        """
        if dict_id not in self.dictionaries:
            raise ValueError(f"Dictionary {dict_id} not found")
        
        dictionary = self.dictionaries[dict_id]
        
        # Remove specified keywords
        existing = set(dictionary["keywords"].get(keyword_type, []))
        remove_set = set(keywords)
        remaining = existing - remove_set
        dictionary["keywords"][keyword_type] = list(remaining)
        
        # Update counts
        dictionary["metadata"]["keyword_counts"][keyword_type] = len(remaining)
        
        # Save updated dictionary
        self._save_dictionary(dict_id, dictionary)
        
        return dictionary
    
    def create_instance(self,
                       instance_id: str,
                       name: str,
                       description: str,
                       dictionaries: List[str],
                       required_counts: Dict[str, Dict[str, int]] = None) -> Dict[str, Any]:
        """
        Create a rule instance by combining dictionaries.
        
        Args:
            instance_id: Unique identifier for the instance
            name: Human-readable name
            description: Description of the instance's purpose
            dictionaries: List of dictionary IDs to include
            required_counts: Requirements for keyword matches by type and dictionary
                           e.g. {
                                 "dict1": {"identifier": 1, "global": 0},
                                 "dict2": {"high_confidence": 1, "general": 2}
                                }
            
        Returns:
            The created instance object
        """
        # Validate dictionaries exist
        for dict_id in dictionaries:
            if dict_id not in self.dictionaries:
                raise ValueError(f"Dictionary {dict_id} not found")
        
        # Set default required counts if not provided
        if not required_counts:
            required_counts = {}
            for dict_id in dictionaries:
                required_counts[dict_id] = {
                    KeywordType.IDENTIFIER: 1,
                    KeywordType.GLOBAL: 1,
                    KeywordType.HIGH_CONFIDENCE: 1,
                    KeywordType.GENERAL: 2
                }
        
        # Create instance object
        instance = {
            "id": instance_id,
            "name": name,
            "description": description,
            "dictionaries": dictionaries,
            "required_counts": required_counts,
            "metadata": {
                "created_at": None,  # Would be set by database
                "updated_at": None
            }
        }
        
        # Save to memory
        self.instances[instance_id] = instance
        
        # Save to storage
        self._save_instance(instance_id, instance)
        
        return instance
    
    def _save_instance(self, instance_id: str, instance: Dict[str, Any]):
        """Save an instance to storage."""
        inst_dir = os.path.join(self.storage_dir, "instances")
        os.makedirs(inst_dir, exist_ok=True)
        
        inst_path = os.path.join(inst_dir, f"{instance_id}.json")
        with open(inst_path, 'w') as f:
            json.dump(instance, f, indent=2)
        
        self.logger.info(f"Saved instance: {instance_id}")
    
    def get_instance(self, instance_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve an instance by ID.
        
        Args:
            instance_id: ID of the instance to retrieve
            
        Returns:
            Instance object or None if not found
        """
        return self.instances.get(instance_id)
    
    def update_instance(self,
                       instance_id: str,
                       updates: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update an instance with new values.
        
        Args:
            instance_id: ID of the instance to update
            updates: Dictionary of values to update
            
        Returns:
            Updated instance object
        """
        if instance_id not in self.instances:
            raise ValueError(f"Instance {instance_id} not found")
        
        instance = self.instances[instance_id]
        
        # Update simple fields
        for field in ["name", "description"]:
            if field in updates:
                instance[field] = updates[field]
        
        # Update dictionaries if provided
        if "dictionaries" in updates:
            for dict_id in updates["dictionaries"]:
                if dict_id not in self.dictionaries:
                    raise ValueError(f"Dictionary {dict_id} not found")
            instance["dictionaries"] = updates["dictionaries"]
        
        # Update required counts if provided
        if "required_counts" in updates:
            instance["required_counts"] = updates["required_counts"]
        
        # Save updated instance
        self._save_instance(instance_id, instance)
        
        return instance
    
    def delete_instance(self, instance_id: str) -> bool:
        """
        Delete an instance.
        
        Args:
            instance_id: ID of the instance to delete
            
        Returns:
            True if deleted, False if not found
        """
        if instance_id not in self.instances:
            return False
        
        # Remove from memory
        del self.instances[instance_id]
        
        # Remove from storage
        inst_path = os.path.join(self.storage_dir, "instances", f"{instance_id}.json")
        if os.path.exists(inst_path):
            os.remove(inst_path)
            self.logger.info(f"Deleted instance: {instance_id}")
        
        return True
    
    def get_instance_keywords(self, instance_id: str) -> Dict[str, Dict[str, List[str]]]:
        """
        Get all keywords for an instance, organized by dictionary and type.
        
        Args:
            instance_id: ID of the instance
            
        Returns:
            Dict of keywords by dictionary and type
        """
        if instance_id not in self.instances:
            raise ValueError(f"Instance {instance_id} not found")
        
        instance = self.instances[instance_id]
        result = {}
        
        for dict_id in instance["dictionaries"]:
            dictionary = self.dictionaries.get(dict_id)
            if dictionary:
                result[dict_id] = dictionary["keywords"]
        
        return result
    
    def get_flattened_instance_keywords(self, instance_id: str) -> Dict[str, List[str]]:
        """
        Get all keywords for an instance, flattened by type.
        
        Args:
            instance_id: ID of the instance
            
        Returns:
            Dict of keywords by type
        """
        if instance_id not in self.instances:
            raise ValueError(f"Instance {instance_id} not found")
        
        instance = self.instances[instance_id]
        result = {
            KeywordType.IDENTIFIER: [],
            KeywordType.GLOBAL: [],
            KeywordType.HIGH_CONFIDENCE: [],
            KeywordType.GENERAL: []
        }
        
        for dict_id in instance["dictionaries"]:
            dictionary = self.dictionaries.get(dict_id)
            if dictionary:
                for kw_type in result:
                    result[kw_type].extend(dictionary["keywords"].get(kw_type, []))
        
        # Remove duplicates
        for kw_type in result:
            result[kw_type] = list(set(result[kw_type]))
        
        return result