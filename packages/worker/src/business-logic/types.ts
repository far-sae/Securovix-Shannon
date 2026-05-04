export interface DomainEntity {
  name: string;
  fields: EntityField[];
  relationships: EntityRelation[];
}

export interface EntityField {
  name: string;
  type: string;
  constraints: string[];
  sensitive: boolean;
}

export interface EntityRelation {
  target: string;
  type: 'has-many' | 'belongs-to' | 'has-one';
  cascadeRules: string[];
}

export interface WorkflowState {
  id: string;
  name: string;
  endpoint: string;
  requiredRole?: string;
  expectedPreconditions: string[];
}

export interface WorkflowTransition {
  from: string;
  to: string;
  trigger: string;
  guards: string[];
  sideEffects: string[];
}

export interface StateMachine {
  name: string;
  states: WorkflowState[];
  transitions: WorkflowTransition[];
  initialState: string;
  terminalStates: string[];
}

export type LogicFlawType =
  | 'state-skip'
  | 'price-manipulation'
  | 'race-condition'
  | 'token-reuse'
  | 'privilege-escalation'
  | 'workflow-bypass'
  | 'parameter-tampering';

export interface LogicFlaw {
  id: string;
  type: LogicFlawType;
  workflow: string;
  description: string;
  affectedTransition: WorkflowTransition;
  attackVector: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  businessImpact: string;
}
