import { PackageStageError } from './profile.js';
import type { PackageStageState } from './types.js';

const NEXT_STATES: Readonly<Record<PackageStageState, readonly PackageStageState[]>> = Object.freeze({
  PROFILE_SELECTED: ['METADATA_CONFIRMING', 'FAILED_QUARANTINE'],
  METADATA_CONFIRMING: ['PLAN_READY', 'FAILED_QUARANTINE'],
  PLAN_READY: ['STAGE_APPROVAL_PENDING', 'FAILED_QUARANTINE'],
  STAGE_APPROVAL_PENDING: ['DOWNLOADING', 'FAILED_QUARANTINE'],
  DOWNLOADING: ['ARTIFACTS_VERIFIED', 'FAILED_QUARANTINE'],
  ARTIFACTS_VERIFIED: ['ARCHIVES_PREFLIGHTED', 'FAILED_QUARANTINE'],
  ARCHIVES_PREFLIGHTED: ['MATERIALIZING', 'FAILED_QUARANTINE'],
  MATERIALIZING: ['TREE_VERIFIED', 'FAILED_QUARANTINE'],
  TREE_VERIFIED: ['READY_TO_COMMIT', 'FAILED_QUARANTINE'],
  READY_TO_COMMIT: ['READY', 'FAILED_QUARANTINE'],
  READY: ['STARTUP_APPROVAL_PENDING', 'INVALID'],
  STARTUP_APPROVAL_PENDING: ['STARTING', 'INVALID'],
  STARTING: ['ACTIVE', 'TERMINATED_INCOMPLETE', 'INVALID'],
  ACTIVE: ['STOPPED', 'ACTIVE_UNKNOWN', 'TERMINATED_INCOMPLETE'],
  STOPPED: [],
  FAILED_QUARANTINE: [],
  INVALID: [],
  ACTIVE_UNKNOWN: ['STOPPED', 'TERMINATED_INCOMPLETE'],
  TERMINATED_INCOMPLETE: [],
});

export class PackageStageStateMachine {
  #state: PackageStageState;

  constructor(initial: PackageStageState = 'PROFILE_SELECTED') {
    this.#state = initial;
  }

  get state(): PackageStageState {
    return this.#state;
  }

  transition(next: PackageStageState): PackageStageState {
    if (!NEXT_STATES[this.#state].includes(next)) {
      throw new PackageStageError('state_transition_invalid');
    }
    this.#state = next;
    return this.#state;
  }
}
