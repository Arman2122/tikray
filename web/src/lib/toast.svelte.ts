export type ToastKind = 'ok' | 'danger' | 'warn' | 'info';

export interface ToastItem {
  id: number;
  kind: ToastKind;
  message: string;
}

let nextId = 1;

class ToastStore {
  items = $state<ToastItem[]>([]);

  push(kind: ToastKind, message: string, ttlMs = 4500): void {
    const id = nextId++;
    this.items = [...this.items, { id, kind, message }];
    if (ttlMs > 0) {
      setTimeout(() => this.dismiss(id), ttlMs);
    }
  }

  ok(msg: string): void {
    this.push('ok', msg);
  }
  err(msg: string): void {
    this.push('danger', msg, 7000);
  }
  warn(msg: string): void {
    this.push('warn', msg, 6000);
  }
  info(msg: string): void {
    this.push('info', msg);
  }

  dismiss(id: number): void {
    this.items = this.items.filter((t) => t.id !== id);
  }
}

export const toast = new ToastStore();
