import {
  issueState,
  consumeState,
  __clearStateStoreForTests,
} from './state.store';

describe('state store', () => {
  beforeEach(() => {
    __clearStateStoreForTests();
  });

  it('issueState returns a non-empty string', () => {
    const s = issueState('verifier-1');
    expect(typeof s).toBe('string');
    expect(s.length).toBeGreaterThan(0);
  });

  it('consumeState returns the codeVerifier for a freshly issued state', () => {
    const s = issueState('my-verifier');
    expect(consumeState(s)).toEqual({ codeVerifier: 'my-verifier' });
  });

  it('consumeState is single-use — second call returns null', () => {
    const s = issueState('my-verifier');
    expect(consumeState(s)).toEqual({ codeVerifier: 'my-verifier' });
    expect(consumeState(s)).toBeNull();
  });

  it('consumeState returns null for an unknown state', () => {
    expect(consumeState('never-issued')).toBeNull();
  });

  it('consumeState returns null for an expired state', () => {
    const s = issueState('my-verifier');
    const originalNow = Date.now;
    Date.now = () => originalNow() + 61_000;
    try {
      expect(consumeState(s)).toBeNull();
    } finally {
      Date.now = originalNow;
    }
  });

  it('two issued states are different', () => {
    expect(issueState('v1')).not.toBe(issueState('v2'));
  });
});
