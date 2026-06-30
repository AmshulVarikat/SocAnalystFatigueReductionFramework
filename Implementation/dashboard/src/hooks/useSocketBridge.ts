import { useEffect, useRef } from 'react';
import { useInvestigationStore } from '../store/zustandAdapter';
import type { WsMessage } from '../types';

export const useSocketBridge = (url: string = 'ws://localhost:8000/ws') => {
  const socketRef = useRef<WebSocket | null>(null);
  
  const addOrUpdate = useInvestigationStore(state => state.addOrUpdateInvestigation);
  const remove = useInvestigationStore(state => state.removeInvestigation);
  const updateHealth = useInvestigationStore(state => state.updateEngineHealth);
  const setInitial = useInvestigationStore(state => state.setInitialInvestigations);

  useEffect(() => {
    // Initial fetch of active queue via REST
    fetch('http://localhost:8000/api/v1/investigations/active')
      .then(res => res.json())
      .then(data => {
        if (Array.isArray(data)) {
          setInitial(data);
        }
      })
      .catch(err => console.error("Failed to fetch initial investigations", err));

    const connect = () => {
      socketRef.current = new WebSocket(url);

      socketRef.current.onmessage = (event) => {
        try {
          const msg: WsMessage = JSON.parse(event.data);
          
          switch (msg.type) {
            case 'ENGINE_HEALTH':
              updateHealth(msg.payload);
              break;
            case 'INVESTIGATION_OPENED':
            case 'INVESTIGATION_UPDATED':
              addOrUpdate(msg.payload);
              break;
            case 'INVESTIGATION_CLOSED':
              remove(msg.payload.investigation_id);
              break;
            default:
              console.log("Unhandled WS message", msg);
          }
        } catch (e) {
          console.error("Failed to parse WS message", e);
        }
      };

      socketRef.current.onclose = () => {
        console.log("WS closed, retrying in 2s...");
        setTimeout(connect, 2000);
      };
    };

    connect();

    return () => {
      if (socketRef.current) {
        socketRef.current.onclose = null;
        socketRef.current.close();
      }
    };
  }, [url, addOrUpdate, remove, updateHealth, setInitial]);

  const sendCommand = (type: string, payload: any) => {
    if (socketRef.current && socketRef.current.readyState === WebSocket.OPEN) {
      socketRef.current.send(JSON.stringify({ type, payload }));
    }
  };

  return { sendCommand };
};
