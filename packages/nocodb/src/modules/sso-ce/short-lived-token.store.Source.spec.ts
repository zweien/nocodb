import {
  issueShortToken,
  consumeShortToken,
  __clearShortTokenStoreForTests,
} from './short-lived-token.store';

describe('short-lived token store', () => {
  beforeEach(() => {
    __clearShortTokenStoreForTests();
  });

  it('issueShortToken returns a non-empty string', () => {
    const t = issueShortToken({ id: 'u1', email: 'a@b.c' });
    expect(typeof t).toBe('string');
    expect(t.length).toBeGreaterThan(0);
  });

  it('consumeShortToken returns the user for a fresh token', () => {
    const user = { id: 'u1', email: 'a@b.c' };
    const t = issueShortToken(user);
    expect(consumeShortToken(t)).toEqual(user);
  });

  it('consumeShortToken is single-use', () => {
    const user = { id: 'u1', email: 'a@b.c' };
    const t = issueShortToken(user);
    expect(consumeShortToken(t)).toEqual(user);
    expect(consumeShortToken(t)).toBeNull();
  });

  it('consumeShortToken returns null for unknown token', () => {
    expect(consumeShortToken('never-issued')).toBeNull();
  });

  it('consumeShortToken returns null for an expired token', () => {
    const t = issueShortToken({ id: 'u1', email: 'a@b.c' });
    const originalNow = Date.now;
    Date.now = () => originalNow() + 61_000;
    try {
      expect(consumeShortToken(t)).toBeNull();
    } finally {
      Date.now = originalNow;
    }
  });
});
