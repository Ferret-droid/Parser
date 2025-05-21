# CIPHER Application

Content Management System for Sensitive Data

## Overview

CIPHER is an advanced platform for organizations to detect, classify, and manage sensitive content through customizable rules and intelligent analysis. It integrates keyword detection, YARA-X rules, and LLM-based analysis to identify and protect sensitive information.

## Key Features

### Role-Based Access Control (RBAC)
- Multi-tenant architecture with company and role-based access
- Granular permissions for viewing pages and editing capabilities

### Custom Detection Framework ("CIPHER CRYPT")
- Define and manage keywords in customizable dictionaries
- Organize keywords by classification level (Identifier, Global, High Confidence, General)
- Generate YARA-X rules for content matching
- Create LLM guardrails based on keyword rules

### Content Processing Pipeline
- Parse emails and attachments using Apache Tika
- Extract document metadata (creators, recipients, etc.)
- Apply YARA-X rules for keyword matching
- Process through NLP pipeline for entity extraction
- Use LLM for contextual analysis

### Document Upload & Testing
- Manual document uploads to test and refine DLP rule quality
- Vector embeddings for similarity search

### Data Visualization & Analysis
- Create network graphs of sensitive data flows
- Build knowledge graphs connecting DLP incidents and worker roles
- Identify creators and distributors of sensitive content

## Technical Architecture

### Frontend
- React for UI framework
- Mantine component library for design system

### Backend
- Python with FastAPI for backend logic
- Strawberry GraphQL for API implementation
- Milvus for vector embeddings and classification
- MongoDB for data storage
- Apache Tika for content parsing
- YARA-X rules for content scanning

## Getting Started

### Prerequisites
- Docker and Docker Compose
- Python 3.10+
- Node.js 18+

### Installation

1. Clone the repository
```bash
git clone https://github.com/yourusername/cipher-app.git
cd cipher-app
```

2. Start the application with Docker Compose
```bash
docker-compose up -d
```

3. Access the application
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- GraphQL Playground: http://localhost:8000/graphql

## Development

### Backend Development

1. Setup virtual environment
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

2. Run the backend locally
```bash
uvicorn src.main:app --reload
```

### Frontend Development

1. Install dependencies
```bash
cd frontend
npm install
```

2. Run the frontend locally
```bash
npm start
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.