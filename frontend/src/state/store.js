const state = {
  user: null,
  loadingUser: false,
};

const listeners = new Set();

export const store = {
  get() {
    return state;
  },

  set(patch) {
    Object.assign(state, patch);
    listeners.forEach((listener) => listener(state));
  },

  subscribe(listener) {
    listeners.add(listener);
    return () => listeners.delete(listener);
  },
};
