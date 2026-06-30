import { create } from 'zustand';
import { useShallow } from 'zustand/react/shallow';
import type { Investigation, EngineHealth } from '../types';

interface InvestigationState {
  investigations: Record<string, Investigation>;
  engineHealth: EngineHealth;
  sortedQueue: Investigation[];
  
  // Actions
  addOrUpdateInvestigation: (inv: Investigation) => void;
  removeInvestigation: (id: string) => void;
  updateEngineHealth: (health: EngineHealth) => void;
  setInitialInvestigations: (invs: Investigation[]) => void;
}

export const useInvestigationStore = create<InvestigationState>((set) => ({
  investigations: {},
  engineHealth: { eps: 0, queue_depth: 0 },
  sortedQueue: [],

  addOrUpdateInvestigation: (inv) =>
    set((state) => {
      const newInvs = { ...state.investigations, [inv.investigation_id]: inv };
      const sorted = Object.values(newInvs).sort((a, b) => b.current_priority - a.current_priority);
      return { investigations: newInvs, sortedQueue: sorted };
    }),

  removeInvestigation: (id) =>
    set((state) => {
      const newInvs = { ...state.investigations };
      delete newInvs[id];
      const sorted = Object.values(newInvs).sort((a, b) => b.current_priority - a.current_priority);
      return { investigations: newInvs, sortedQueue: sorted };
    }),

  updateEngineHealth: (health) => set({ engineHealth: health }),
  
  setInitialInvestigations: (invs) => 
    set(() => {
      const newInvs: Record<string, Investigation> = {};
      invs.forEach(i => newInvs[i.investigation_id] = i);
      const sorted = [...invs].sort((a, b) => b.current_priority - a.current_priority);
      return { investigations: newInvs, sortedQueue: sorted };
    })
}));

// Adapter hook to abstract away Zustand
export const useInvestigationQueue = () => {
  return useInvestigationStore(
    useShallow((state) => ({
      queue: state.sortedQueue,
      health: state.engineHealth,
    }))
  );
};
