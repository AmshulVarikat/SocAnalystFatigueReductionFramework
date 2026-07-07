import asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Dict, Any, Optional

from .websockets import manager
from .database import get_db, ProcessedAlert, Investigation, InvestigationMapping

app = FastAPI(title="Context-Aware SOC Dashboard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # For development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Background task to send engine health
async def broadcast_engine_health():
    while True:
        await asyncio.sleep(2)
        # Mock engine health metrics, could be updated by Orchestrator POSTs
        health_data = {
            "type": "ENGINE_HEALTH",
            "payload": {
                "eps": 1250, # Example
                "queue_depth": 14
            }
        }
        await manager.broadcast(health_data)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(broadcast_engine_health())

# -----------------------------------------------------
# WebSocket Endpoint
# -----------------------------------------------------
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Handle client-to-server commands
            import json
            try:
                msg = json.loads(data)
                if msg.get("type") == "UPDATE_INVESTIGATION_STATUS":
                    # Update DB (mock for now) and broadcast or acknowledge
                    pass
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# -----------------------------------------------------
# Internal Ingest Endpoint (From Orchestrator)
# -----------------------------------------------------
@app.post("/api/internal/event_ingest")
async def internal_event_ingest(request: Request):
    """
    Receives events from the decoupled Orchestrator and broadcasts them to the WebSockets.
    """
    payload = await request.json()
    # payload format could be: {"type": "INVESTIGATION_OPENED", "payload": {...}}
    await manager.broadcast(payload)
    return {"status": "success"}

# -----------------------------------------------------
# REST API (Deep Dives)
# -----------------------------------------------------
@app.get("/api/v1/investigations/active")
def get_active_investigations(db: Session = Depends(get_db)):
    investigations = db.query(Investigation).filter(Investigation.status != "CLOSED").all()
    
    result = []
    for inv in investigations:
        result.append({
            "investigation_id": inv.investigation_id,
            "status": inv.status,
            "created_at": inv.created_at,
            "rule_name": inv.rule_name,
            "current_priority": inv.current_priority
        })
    return result

@app.get("/api/v1/investigations/all")
def get_all_investigations(db: Session = Depends(get_db)):
    investigations = db.query(Investigation).all()
    
    result = []
    for inv in investigations:
        result.append({
            "investigation_id": inv.investigation_id,
            "status": inv.status,
            "created_at": inv.created_at,
            "rule_name": inv.rule_name,
            "current_priority": inv.current_priority
        })
    return result

@app.post("/api/v1/investigations/{inv_id}/ack")
def ack_investigation(inv_id: str, db: Session = Depends(get_db)):
    inv = db.query(Investigation).filter(Investigation.investigation_id == inv_id).first()
    if inv:
        inv.status = "CLOSED"
        db.commit()
        return {"status": "success"}
    raise HTTPException(status_code=404, detail="Investigation not found")

@app.get("/api/v1/alerts")
def get_unified_alerts(db: Session = Depends(get_db)):
    """Returns active investigations AND likely benign alerts unified."""
    investigations = db.query(Investigation).filter(Investigation.status != "CLOSED").all()
    benign_alerts = db.query(ProcessedAlert).filter(ProcessedAlert.classification == "Likely Benign").all()
    
    result = []
    for inv in investigations:
        result.append({
            "id": inv.investigation_id,
            "type": "investigation",
            "priority": inv.current_priority,
            "rule_name": inv.rule_name,
            "created_at": inv.created_at,
            "status": inv.status,
        })
    for alert in benign_alerts:
        result.append({
            "id": f"alert-{alert.id}",
            "type": "alert",
            "priority": alert.risk_score,
            "rule_name": f"{alert.rule_id} (Benign)",
            "created_at": alert.timestamp,
            "status": "OPEN",
        })
    return result

@app.get("/api/v1/alerts/false-positives")
def get_false_positives(db: Session = Depends(get_db)):
    alerts = db.query(ProcessedAlert).filter(ProcessedAlert.classification == "Likely False Positive").all()
    result = []
    import json
    for alert in alerts:
        try:
            payload = json.loads(alert.full_alert_payload)
            payload["_internal_id"] = alert.id
            result.append(payload)
        except Exception:
            pass
    return result

@app.get("/api/v1/investigations/{inv_id}/alerts")
def get_investigation_alerts(inv_id: str, db: Session = Depends(get_db)):
    mappings = db.query(InvestigationMapping).filter(InvestigationMapping.investigation_id == inv_id).all()
    if not mappings:
        raise HTTPException(status_code=404, detail="Investigation not found")
        
    alerts = []
    import json
    for mapping in mappings:
        alert_db = mapping.alert
        if alert_db:
            alerts.append(json.loads(alert_db.full_alert_payload))
            
    return alerts

@app.get("/api/v1/investigations/{inv_id}/graph")
def get_investigation_graph(inv_id: str, db: Session = Depends(get_db)):
    # Mocking graph data structure for React Flow
    mappings = db.query(InvestigationMapping).filter(InvestigationMapping.investigation_id == inv_id).all()
    if not mappings:
        raise HTTPException(status_code=404, detail="Investigation not found")
        
    nodes = []
    edges = []
    
    import json
    for i, mapping in enumerate(mappings):
        alert_db = mapping.alert
        if alert_db:
            # Simple node generation
            node_id = f"alert-{alert_db.id}"
            nodes.append({
                "id": node_id,
                "data": {"label": f"{alert_db.rule_id} ({alert_db.src_ip} -> {alert_db.dest_ip})"},
                "position": {"x": 250, "y": i * 100}
            })
            if i > 0:
                prev_node_id = f"alert-{mappings[i-1].alert.id}"
                edges.append({
                    "id": f"e-{prev_node_id}-{node_id}",
                    "source": prev_node_id,
                    "target": node_id
                })
                
    return {"nodes": nodes, "edges": edges}

@app.get("/api/v1/metrics/historical")
def get_historical_metrics(timeframe: str = "24h", db: Session = Depends(get_db)):
    # Mock aggregated DB math
    return {
        "workload_reduction": 85.4,
        "false_positive_reduction": 60.2,
        "mttt": "4.2m",
        "chart_data": [
            {"time": "10:00", "raw_alerts": 1200, "correlated": 15},
            {"time": "11:00", "raw_alerts": 3400, "correlated": 28},
            {"time": "12:00", "raw_alerts": 800, "correlated": 5},
        ]
    }

class SearchRequest(BaseModel):
    query: str

@app.post("/api/v1/investigations/search")
def search_investigations(request: SearchRequest, db: Session = Depends(get_db)):
    # Dummy implementation for KQL string
    return []

class SimulationControlRequest(BaseModel):
    command: str
    speed: int

@app.post("/api/v1/simulation/control")
def control_simulation(request: SimulationControlRequest):
    # This would interact with the orchestrator if it's running.
    # Since it's decoupled, we might need a redis channel or similar if two-way is required.
    return {"status": "acknowledged"}

class RulesConfig(BaseModel):
    rules: Dict[str, Any]

@app.post("/api/v1/config/rules")
def update_rules(config: RulesConfig):
    # Save the new rules.json and trigger a hot-reload in Orchestrator (if possible)
    return {"status": "saved"}
