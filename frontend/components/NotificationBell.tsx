'use client';

import { useEffect, useRef, useState, useCallback } from 'react';
import { Bell, ShieldAlert, CheckCircle2, Info } from 'lucide-react';
import { mainApi } from '@/lib/api';

interface NotificationItem {
  id: string;
  type: 'critical' | 'success' | 'info';
  title: string;
  message: string;
  timestamp: string;
}

const ICONS: Record<NotificationItem['type'], typeof Bell> = {
  critical: ShieldAlert,
  success: CheckCircle2,
  info: Info,
};

const TONE_CLASSES: Record<NotificationItem['type'], string> = {
  critical: 'text-accent-rose bg-accent-rose-soft',
  success: 'text-accent-emerald bg-accent-emerald-soft',
  info: 'text-accent-cyan bg-accent-cyan-soft',
};

function timeAgo(iso: string) {
  const diffMs = Date.now() - new Date(iso).getTime();
  const mins = Math.max(0, Math.floor(diffMs / 60000));
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export default function NotificationBell() {
  const [open, setOpen] = useState(false);
  const [items, setItems] = useState<NotificationItem[]>([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [fetchFailed, setFetchFailed] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let active = true;
    const fetchNotifications = async () => {
      try {
        const { data } = await mainApi.get('/api/proxy/api/v1/notifications');
        if (active) {
          setItems(data.notifications || []);
          setUnreadCount(data.unreadCount || 0);
          setFetchFailed(false);
        }
      } catch {
        // Never fabricate a notification to fill the gap — an invented "PR
        // #42 Verified" event could be mistaken for something that actually
        // happened. Show an honest "couldn't load" state instead.
        if (active) {
          setItems([]);
          setUnreadCount(0);
          setFetchFailed(true);
        }
      } finally {
        if (active) setLoading(false);
      }
    };

    fetchNotifications();
    const interval = setInterval(fetchNotifications, 30000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, []);

  useEffect(() => {
    function onClickOutside(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener('mousedown', onClickOutside);
    return () => document.removeEventListener('mousedown', onClickOutside);
  }, []);

  const markAllRead = async () => {
    if (items.length === 0) return;
    setUnreadCount(0);
    try {
      await mainApi.post('/api/proxy/api/v1/notifications/read', { lastReadId: items[0].id });
    } catch {
      // best-effort
    }
  };

  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        onClick={() => {
          const next = !open;
          setOpen(next);
          if (next) markAllRead();
        }}
        aria-label={`Security notifications: ${unreadCount} unread`}
        title={`Notifications (${unreadCount} unread)`}
        className="relative w-8 h-8 rounded-lg border border-border-default bg-bg-card hover:bg-bg-subtle text-text-secondary hover:text-text-primary transition-colors flex items-center justify-center shadow-sm"
      >
        <Bell size={15} strokeWidth={1.75} />
        {unreadCount > 0 && (
          <span className="absolute -top-1 -right-1 min-w-[16px] h-4 px-1 rounded-full bg-accent-rose text-white text-[10px] font-mono font-bold flex items-center justify-center leading-none">
            {unreadCount > 9 ? '9+' : unreadCount}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 mt-2 w-80 max-w-[calc(100vw-2rem)] bg-bg-card border border-border-hover rounded-2xl shadow-2xl z-50 overflow-hidden animate-fade-rise-in">
          <div className="px-4 py-3 border-b border-border-default flex items-center justify-between">
            <span className="text-xs font-mono font-semibold text-text-primary uppercase tracking-wider">
              Security Telemetry
            </span>
            {items.length > 0 && <span className="text-[11px] font-mono text-text-muted">{items.length} events</span>}
          </div>
          <div className="max-h-80 overflow-y-auto divide-y divide-border-default">
            {loading ? (
              <div className="px-4 py-8 text-center text-xs font-mono text-text-muted">Loading telemetry…</div>
            ) : fetchFailed ? (
              <div className="px-4 py-8 text-center text-xs font-mono text-text-muted">Couldn't load notifications. Try again shortly.</div>
            ) : items.length === 0 ? (
              <div className="px-4 py-8 text-center text-xs font-mono text-text-muted">All systems secure. No alerts.</div>
            ) : (
              items.map((item) => {
                const Icon = ICONS[item.type];
                return (
                  <div key={item.id} className="px-4 py-3 flex gap-3 hover:bg-bg-subtle transition-colors">
                    <div className={`w-7 h-7 rounded-lg shrink-0 flex items-center justify-center ${TONE_CLASSES[item.type]}`}>
                      <Icon size={13} strokeWidth={2} />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="text-xs font-semibold text-text-primary truncate">{item.title}</div>
                      <div className="text-xs text-text-secondary truncate mt-0.5">{item.message}</div>
                      <div className="text-[10px] font-mono text-text-muted mt-1">{timeAgo(item.timestamp)}</div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}
    </div>
  );
}
