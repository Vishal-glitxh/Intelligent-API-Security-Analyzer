import React from 'react';
import { Severity, CorrelationState } from '../../types/findings';
import { ScanStatus } from '../../types/scan';

interface BadgeProps {
  children: React.ReactNode;
  variant?: 'severity' | 'status' | 'correlation' | 'tier' | 'layer' | 'neutral';
  value?: string;
  className?: string;
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  variant = 'neutral',
  value,
  className = '',
}) => {
  const normalized = (value || String(children)).toUpperCase();

  let colorClasses = 'bg-slate-800 text-slate-300 border-slate-700';

  if (variant === 'severity') {
    switch (normalized as Severity) {
      case 'HIGH':
        colorClasses = 'bg-rose-950/70 text-rose-300 border-rose-800/80';
        break;
      case 'MEDIUM':
        colorClasses = 'bg-amber-950/70 text-amber-300 border-amber-800/80';
        break;
      case 'LOW':
        colorClasses = 'bg-blue-950/70 text-blue-300 border-blue-800/80';
        break;
      case 'INFO':
        colorClasses = 'bg-slate-800/70 text-slate-300 border-slate-700/80';
        break;
      default:
        colorClasses = 'bg-rose-950/70 text-rose-300 border-rose-800/80';
        break;
    }
  } else if (variant === 'status') {
    switch (normalized as Uppercase<ScanStatus>) {
      case 'COMPLETED':
        colorClasses = 'bg-emerald-950/70 text-emerald-300 border-emerald-800/80';
        break;
      case 'RUNNING':
        colorClasses = 'bg-cyan-950/70 text-cyan-300 border-cyan-800/80 animate-pulse';
        break;
      case 'QUEUED':
        colorClasses = 'bg-amber-950/70 text-amber-300 border-amber-800/80';
        break;
      case 'FAILED':
        colorClasses = 'bg-rose-950/70 text-rose-300 border-rose-800/80';
        break;
    }
  } else if (variant === 'correlation') {
    switch (normalized as CorrelationState) {
      case 'SUPPORTED':
        colorClasses = 'bg-emerald-950/70 text-emerald-300 border-emerald-800/80';
        break;
      case 'CONTRADICTED':
        colorClasses = 'bg-rose-950/70 text-rose-300 border-rose-800/80';
        break;
      case 'COMPLEMENTARY':
        colorClasses = 'bg-cyan-950/70 text-cyan-300 border-cyan-800/80';
        break;
      case 'INCONCLUSIVE':
        colorClasses = 'bg-slate-800/70 text-slate-400 border-slate-700/80';
        break;
    }
  } else if (variant === 'tier') {
    if (normalized.includes('EXACT') || normalized.includes('TIER_1')) {
      colorClasses = 'bg-emerald-950/70 text-emerald-300 border-emerald-800/80';
    } else if (normalized.includes('PARAMETER') || normalized.includes('TIER_2')) {
      colorClasses = 'bg-cyan-950/70 text-cyan-300 border-cyan-800/80';
    } else {
      colorClasses = 'bg-amber-950/70 text-amber-300 border-amber-800/80';
    }
  } else if (variant === 'layer') {
    if (normalized.includes('CORRELAT')) {
      colorClasses = 'bg-teal-950/70 text-teal-300 border-teal-800/80';
    } else if (normalized.includes('SPEC')) {
      colorClasses = 'bg-indigo-950/70 text-indigo-300 border-indigo-800/80';
    } else if (normalized.includes('SOURCE')) {
      colorClasses = 'bg-sky-950/70 text-sky-300 border-sky-800/80';
    }
  }

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium border ${colorClasses} ${className}`}
    >
      {children}
    </span>
  );
};

export const StatusBadge: React.FC<{ status: string }> = ({ status }) => (
  <Badge variant="status" value={status}>
    {status.toUpperCase()}
  </Badge>
);

export const SeverityBadge: React.FC<{ severity: string }> = ({ severity }) => (
  <Badge variant="severity" value={severity}>
    {severity.toUpperCase()}
  </Badge>
);

export const CorrelationBadge: React.FC<{ state: string }> = ({ state }) => (
  <Badge variant="correlation" value={state}>
    {state.toUpperCase()}
  </Badge>
);

export const TierBadge: React.FC<{ tier: string }> = ({ tier }) => (
  <Badge variant="tier" value={tier}>
    {tier.replace('TIER_', 'T')}
  </Badge>
);

export const LayerBadge: React.FC<{ layer?: string }> = ({ layer }) => (
  <Badge variant="layer" value={layer || 'CORRELATED'}>
    {(layer || 'CORRELATED').toUpperCase()}
  </Badge>
);

export const CategoryBadge: React.FC<{ category: string }> = ({ category }) => (
  <Badge variant="neutral">
    {category}
  </Badge>
);
