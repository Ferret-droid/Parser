import os
import logging
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from strawberry.fastapi import GraphQLRouter
from contextlib import asynccontextmanager

from .routes.graphql_schema import schema
from .integrations.mongodb.db_connection import MongoDBConnection
from .integrations.yara.yara_engine import YaraXEngine
from .services.keyword_manager import KeywordManager
from .services.content_processor import ContentProcessor
from .integrations.mcp.mcp_keyword_engine import KeywordMCPEngine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cipher_app.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("cipher_app")

# Service instances
db_connection = None
yara_engine = None
keyword_manager = None
content_processor = None
keyword_mcp_engine = None

# Services dictionary for GraphQL context
services = {}

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize services
    global db_connection, yara_engine, keyword_manager, content_processor, keyword_mcp_engine, services
    
    logger.info("Initializing CIPHER application services")
    
    # Initialize MongoDB connection
    mongodb_uri = os.environ.get("MONGODB_URI", "mongodb://localhost:27017/")
    db_name = os.environ.get("MONGODB_DB", "cipher_db")
    
    try:
        db_connection = MongoDBConnection(uri=mongodb_uri, db_name=db_name)
        db_connection.connect()
        db_connection.create_indexes()
        logger.info("MongoDB connection established")
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB: {str(e)}")
        db_connection = None
    
    # Initialize YARA-X engine
    try:
        yara_engine = YaraXEngine()
        logger.info("YARA-X engine initialized")
    except Exception as e:
        logger.error(f"Failed to initialize YARA-X engine: {str(e)}")
        yara_engine = None
    
    # Initialize Keyword Manager
    keyword_manager = KeywordManager()
    logger.info("Keyword Manager initialized")
    
    # Initialize Content Processor
    if db_connection:
        content_processor = ContentProcessor(
            db_connection=db_connection,
            yara_engine=yara_engine,
            keyword_manager=keyword_manager
        )
        logger.info("Content Processor initialized")
    
    # Initialize Keyword MCP Engine
    try:
        mcp_script_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "integrations", "mcp", "keyword_guardrail_server.py"
        )
        keyword_mcp_engine = KeywordMCPEngine(mcp_server_script=mcp_script_path)
        keyword_mcp_engine.start_server()
        logger.info("Keyword MCP Engine initialized")
    except Exception as e:
        logger.error(f"Failed to initialize Keyword MCP Engine: {str(e)}")
        keyword_mcp_engine = None
    
    # Update services dictionary for GraphQL context
    services.update({
        "db_connection": db_connection,
        "yara_engine": yara_engine,
        "keyword_manager": keyword_manager,
        "content_processor": content_processor,
        "keyword_mcp_engine": keyword_mcp_engine,
        # These would be implemented in a full app:
        "content_service": None,
        "rule_service": None,
        "keyword_service": None,
        "search_service": None,
        "audit_service": None,
        "user_service": None,
        "org_service": None
    })
    
    logger.info("All services initialized")
    
    yield
    
    # Cleanup services
    logger.info("Shutting down CIPHER application services")
    
    if keyword_mcp_engine:
        keyword_mcp_engine.stop_server()
        logger.info("Keyword MCP Engine stopped")
    
    if db_connection:
        db_connection.disconnect()
        logger.info("MongoDB connection closed")

# GraphQL context function
async def get_context(request: Request):
    return {
        "request": request,
        **services
    }

# Create GraphQL router
graphql_app = GraphQLRouter(
    schema,
    context_getter=get_context,
)

# Create FastAPI app
app = FastAPI(
    title="CIPHER API",
    description="API for CIPHER Content Management System for Sensitive Data",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add GraphQL endpoint
app.include_router(graphql_app, prefix="/graphql")

# Exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Global exception: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"message": "Internal server error", "details": str(exc)}
    )

# Root endpoint
@app.get("/")
async def root():
    return {
        "message": "Welcome to CIPHER API",
        "version": "1.0.0",
        "graphql_endpoint": "/graphql",
        "status": "online",
        "services": {
            "mongodb": "online" if db_connection else "offline",
            "yara_engine": "online" if yara_engine else "offline", 
            "keyword_manager": "online" if keyword_manager else "offline",
            "content_processor": "online" if content_processor else "offline",
            "keyword_mcp_engine": "online" if keyword_mcp_engine else "offline"
        }
    }

# Health check endpoint
@app.get("/health")
async def health():
    # Check database connection
    db_status = "healthy"
    if db_connection:
        try:
            db_connection.client.server_info()
        except Exception as e:
            db_status = f"unhealthy: {str(e)}"
    else:
        db_status = "not initialized"
    
    return {
        "status": "healthy",
        "services": {
            "api": "healthy",
            "database": db_status,
            "yara_engine": "healthy" if yara_engine else "not initialized",
            "keyword_mcp_engine": "healthy" if keyword_mcp_engine and keyword_mcp_engine.mcp_process and keyword_mcp_engine.mcp_process.poll() is None else "not running"
        }
    }

# Run with:
# uvicorn src.main:app --reload