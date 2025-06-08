graph_processor.py
This Python script contains the core logic for the Social Trust Graph Agent. It is responsible for building, updating, and analyzing a dynamic trust graph based on various interactions (collaborations, endorsements, team formations).

🎯 Purpose
Graph Construction: Uses NetworkX to build a directed graph where nodes represent entities (founders, contributors, investors) and edges represent relationships.

Data Ingestion: Provides methods to add different types of relationships (collaborations, endorsements, team formations) with associated weights.

Trust Scoring: Calculates a dynamic trust score for each entity using a combination of graph algorithms like PageRank (for influence) and weighted degree (for activity).

Graph Hashing: Generates a deterministic cryptographic hash of the entire graph's state, crucial for on-chain integrity verification.

🛠️ Dependencies
networkx: For graph data structures and algorithms.

pip install networkx

hashlib: (Built-in Python library) For cryptographic hashing.

json: (Built-in Python library) For deterministic serialization.

asyncio: (Built-in Python library) For asynchronous operations.

🚀 Usage
This module is primarily designed to be imported and used by the social_trust_graph_agent.py LangGraph. It can be tested independently:

cd Social_Trust_Graph_Agent
python graph_processor.py
