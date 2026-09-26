import type { RouterConfig } from './config.ts';

export type RouterState = 'stopped' | 'starting' | 'running' | 'stopping' | 'failed';
export interface RouterComponent {
  readonly name: string;
  start(config: RouterConfig, signal: AbortSignal): Promise<void>;
  stop(): Promise<void>;
}
export type RouterStatus = { state: RouterState; startedComponents: string[]; error?: string };

/** Lifecycle coordinator only. It does not implement I2P transport or routing protocols. */
export class RouterCore {
  private state: RouterState = 'stopped';
  private started: RouterComponent[] = [];
  private operation: Promise<void> | undefined;
  private lastError: string | undefined;
  private controller = new AbortController();
  readonly config: RouterConfig;
  private readonly components: readonly RouterComponent[];

  constructor(config: RouterConfig, components: readonly RouterComponent[]) {
    this.config = config;
    this.components = components;
    const names = components.map(component => component.name);
    if (names.some(name => !name.trim()) || new Set(names).size !== names.length) throw new Error('Router component names must be non-empty and unique');
  }

  status(): RouterStatus {
    return { state: this.state, startedComponents: this.started.map(component => component.name), ...(this.lastError ? { error: this.lastError } : {}) };
  }

  start(): Promise<void> {
    if (this.state === 'running') return Promise.resolve();
    if (this.state === 'starting' && this.operation) return this.operation;
    if (this.state !== 'stopped') return Promise.reject(new Error(`Cannot start router while state is ${this.state}`));
    this.state = 'starting'; this.lastError = undefined;
    this.controller = new AbortController();
    this.operation = this.startComponents();
    return this.operation;
  }

  private async startComponents(): Promise<void> {
    try {
      for (const component of this.components) {
        if (this.controller.signal.aborted) throw new Error('Router startup aborted');
        await component.start(this.config, this.controller.signal);
        this.started.push(component);
      }
      this.state = 'running';
    } catch (error) {
      this.lastError = error instanceof Error ? error.message : String(error);
      this.state = 'failed';
      await this.stopStarted();
      throw error;
    } finally { this.operation = undefined; }
  }

  async stop(): Promise<void> {
    if (this.state === 'stopped') return;
    if (this.state === 'starting') {
      this.controller.abort();
      try { await this.operation; } catch { /* startup failure is reflected in status */ }
    }
    if (this.status().state === 'stopped') return;
    this.state = 'stopping';
    const errors = await this.stopStarted();
    this.state = errors.length ? 'failed' : 'stopped';
    if (errors.length) {
      this.lastError = `Failed to stop component(s): ${errors.map(item => item.name).join(', ')}`;
      throw new Error(this.lastError);
    }
    this.lastError = undefined;
  }

  private async stopStarted(): Promise<RouterComponent[]> {
    const failed: RouterComponent[] = [];
    while (this.started.length) {
      const component = this.started.pop()!;
      try { await component.stop(); } catch { failed.push(component); }
    }
    return failed;
  }
}
