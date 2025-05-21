import logging
import os
from typing import Dict, List, Any, Optional
from pymongo import MongoClient
from pymongo.database import Database
from pymongo.collection import Collection
from pymongo.errors import ConnectionError, ConfigurationError, ServerSelectionTimeoutError

class MongoDBConnection:
    """
    Handles MongoDB connection and provides access to collections
    """
    
    def __init__(self, 
                uri: Optional[str] = None,
                db_name: str = "cipher_db",
                connect_timeout: int = 5000):
        """
        Initialize MongoDB connection.
        
        Args:
            uri: MongoDB connection URI (defaults to environment variable MONGODB_URI)
            db_name: Database name (defaults to environment variable MONGODB_DB or "cipher_db")
            connect_timeout: Connection timeout in milliseconds
        """
        self.logger = logging.getLogger(__name__)
        
        # Get URI from environment if not provided
        if not uri:
            uri = os.environ.get("MONGODB_URI", "mongodb://localhost:27017/")
        
        # Get DB name from environment if specified
        db_name = os.environ.get("MONGODB_DB", db_name)
        
        self.uri = uri
        self.db_name = db_name
        self.connect_timeout = connect_timeout
        self.client = None
        self.db = None
        
        # Collection references
        self._collections = {}
    
    def connect(self) -> Database:
        """
        Connect to MongoDB.
        
        Returns:
            MongoDB database object
        """
        try:
            self.logger.info(f"Connecting to MongoDB at {self.uri}")
            
            # Create client with appropriate timeout
            self.client = MongoClient(
                self.uri,
                serverSelectionTimeoutMS=self.connect_timeout
            )
            
            # Check if connection is successful
            self.client.server_info()
            
            # Get database
            self.db = self.client[self.db_name]
            
            self.logger.info(f"Connected to MongoDB database: {self.db_name}")
            return self.db
            
        except (ConnectionError, ConfigurationError, ServerSelectionTimeoutError) as e:
            self.logger.error(f"Failed to connect to MongoDB: {str(e)}")
            raise
    
    def disconnect(self):
        """Close MongoDB connection."""
        if self.client:
            self.client.close()
            self.logger.info("Disconnected from MongoDB")
    
    def get_collection(self, collection_name: str) -> Collection:
        """
        Get a MongoDB collection, creating it if it doesn't exist.
        
        Args:
            collection_name: Name of the collection
            
        Returns:
            MongoDB collection object
        """
        if not self.db:
            self.connect()
        
        if collection_name not in self._collections:
            self._collections[collection_name] = self.db[collection_name]
        
        return self._collections[collection_name]
    
    def create_indexes(self):
        """Create indexes for all collections."""
        if not self.db:
            self.connect()
        
        # Content collection indexes
        content_col = self.get_collection("content")
        content_col.create_index("org_id")
        content_col.create_index("md5_hash")
        content_col.create_index("sha256_hash")
        content_col.create_index("sensitivity_level")
        content_col.create_index("processing_status")
        content_col.create_index("content_type")
        content_col.create_index("tags")
        
        # Yara rules collection indexes
        rules_col = self.get_collection("yara_rules")
        rules_col.create_index("org_id")
        rules_col.create_index("name")
        rules_col.create_index("is_active")
        rules_col.create_index("instance_id")
        rules_col.create_index("tags")
        
        # Users collection indexes
        users_col = self.get_collection("users")
        users_col.create_index("username", unique=True)
        users_col.create_index("email", unique=True)
        users_col.create_index("org_id")
        users_col.create_index("roles")
        
        # Organizations collection indexes
        orgs_col = self.get_collection("organizations")
        orgs_col.create_index("name", unique=True)
        orgs_col.create_index("tenant_id")
        
        # Audit logs collection indexes
        audit_col = self.get_collection("audit_logs")
        audit_col.create_index("timestamp")
        audit_col.create_index("user_id")
        audit_col.create_index("org_id")
        audit_col.create_index("action")
        
        # Keyword dictionaries collection indexes
        kw_dict_col = self.get_collection("keyword_dictionaries")
        kw_dict_col.create_index("org_id")
        kw_dict_col.create_index("project_id")
        
        # Keyword instances collection indexes
        kw_inst_col = self.get_collection("keyword_instances")
        kw_inst_col.create_index("org_id")
        
        self.logger.info("Created MongoDB indexes")
        
    def drop_database(self):
        """Drop the entire database. Use with caution!"""
        if not self.db:
            self.connect()
            
        self.client.drop_database(self.db_name)
        self.logger.warning(f"Dropped database: {self.db_name}")
    
    def get_collection_stats(self) -> Dict[str, int]:
        """
        Get document counts for each collection.
        
        Returns:
            Dictionary with collection names and counts
        """
        if not self.db:
            self.connect()
            
        result = {}
        for collection_name in self.db.list_collection_names():
            result[collection_name] = self.db[collection_name].count_documents({})
            
        return result