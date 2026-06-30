export interface Investigation {
  investigation_id: string;
  status: 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED' | 'FALSE_POSITIVE' | 'CLOSED';
  created_at: string;
  rule_name: string;
  current_priority: number;
}

export interface EngineHealth {
  eps: number;
  queue_depth: number;
}

export interface WsMessage {
  type: 'INVESTIGATION_OPENED' | 'INVESTIGATION_UPDATED' | 'INVESTIGATION_CLOSED' | 'ENGINE_HEALTH' | 'SIMULATION_STATE';
  payload: any;
}
