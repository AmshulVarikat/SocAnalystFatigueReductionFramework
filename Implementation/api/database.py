import os
from sqlalchemy import create_engine, Column, Integer, String, Float, Text, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "storage", "alerts.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class ProcessedAlert(Base):
    __tablename__ = "processed_alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String, index=True)
    rule_id = Column(String, index=True)
    hostname = Column(String, index=True)
    username = Column(String, index=True)
    src_ip = Column(String, index=True)
    dest_ip = Column(String, index=True)
    process_name = Column(String, index=True)
    file_hash = Column(String, index=True)
    wazuh_level = Column(Integer, index=True)
    mitre_tactic = Column(String, index=True)
    risk_score = Column(Float)
    classification = Column(String)
    full_alert_payload = Column(Text)
    enrichment_data = Column(Text)

class Investigation(Base):
    __tablename__ = "investigations"
    
    investigation_id = Column(String, primary_key=True, index=True)
    status = Column(String)
    created_at = Column(String)
    closed_at = Column(String, nullable=True)
    rule_name = Column(String)
    current_priority = Column(Float, default=0.0)
    alerts_count = Column(Integer, default=1)
    match_values = Column(Text, default="{}")
    observed_progression = Column(Text, default="{}")

class InvestigationMapping(Base):
    __tablename__ = "investigation_mapping"
    
    mapping_id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(String, ForeignKey("investigations.investigation_id"), index=True)
    alert_id = Column(Integer, ForeignKey("processed_alerts.id"))
    
    investigation = relationship("Investigation", backref="mappings")
    alert = relationship("ProcessedAlert")

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
