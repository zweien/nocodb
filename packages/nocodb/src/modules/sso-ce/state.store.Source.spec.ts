import { issueState, consumeState, __clearStateStoreForTests } from './state.store';

describe('state store', () => {
  beforeEach(() => {
    __clearStateStoreForTests();
  });

  it('issueState returns a non-empty string', () => {
    const s = issueState();
    expect(typeof s).toBe('string');
    expect(s.length).toBeGreaterThan(0);
  });

  it('consumeState returns true for a freshly issued state', () => {
    const s = issueState();
    expect(consumeState(s)).toBe(true);
  });

  it('consumeState is single-use — second call returns false', () => {
    const s = issueState();
    expect(consumeState(s)).toBe(true);
    expect(consumeState(s)).toBe(false);
  });

  it('consumeState returns false for an unknown state', () => {
    expect(consumeState('never-issued')).toBe(false);
  });

  it('consumeState returns false for an expired state', () => {
    const s = issueState();
    // Manually backdate the entry by rewriting its createdAt.
    // We rely on the internal TTL check; simulate by injecting an old entry
    // through the public issueState and then advancing Date.now via mock.
    const originalNow = Date.now;
    Date.now = () => originalNow() + 61_000; // 61s later
    try {
      expect(consumeState(s)).toBe(false);
    } finally {
      Date.now = originalNow;
    }
  });

  it('two issued states are different', () => {
    expect(issueState()).not.toBe(issueState());
  });
});
