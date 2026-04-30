import * as React from "react";

export interface SegmentOption<V extends string> {
  value: V;
  label: string;
  count?: number | null;
  icon?: React.ReactNode;
}

interface Props<V extends string> {
  value:    V;
  onChange: (v: V) => void;
  options:  SegmentOption<V>[];
}

export function SegmentedTabs<V extends string>({ value, onChange, options }: Props<V>): React.ReactElement {
  return (
    <div className="vs-segmented" role="tablist">
      {options.map((o) => (
        <button
          key={o.value}
          role="tab"
          aria-selected={value === o.value}
          className={`vs-seg-btn ${value === o.value ? "is-active" : ""}`}
          onClick={() => onChange(o.value)}
        >
          {o.icon}
          <span>{o.label}</span>
          {o.count != null && <span className="vs-seg-count">{o.count}</span>}
        </button>
      ))}
    </div>
  );
}
