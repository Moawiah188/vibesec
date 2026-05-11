// VibeSec icons. 14x14 default, currentColor stroke.
// Faithful TypeScript port of design's icons.jsx.

import * as React from "react";

interface IconProps {
  size?: number;
  stroke?: number;
  fill?: string;
  viewBox?: string;
}

const Icon: React.FC<IconProps & { children?: React.ReactNode; d?: string }> = ({
  size = 14,
  stroke = 1.5,
  fill = "none",
  viewBox = "0 0 16 16",
  children,
  d,
}) => (
  <svg
    width={size}
    height={size}
    viewBox={viewBox}
    fill={fill}
    stroke="currentColor"
    strokeWidth={stroke}
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
  >
    {d ? <path d={d} /> : children}
  </svg>
);

export const Shield: React.FC<IconProps> = (p) => (
  <Icon {...p}>
    <path d="M8 1.5L2.5 3.5v4.2c0 3 2.3 5.7 5.5 6.8 3.2-1.1 5.5-3.8 5.5-6.8V3.5L8 1.5z" />
  </Icon>
);
export const ShieldCheck: React.FC<IconProps> = (p) => (
  <Icon {...p}>
    <path d="M8 1.5L2.5 3.5v4.2c0 3 2.3 5.7 5.5 6.8 3.2-1.1 5.5-3.8 5.5-6.8V3.5L8 1.5z" />
    <path d="M5.5 8l1.8 1.8L10.5 6.5" />
  </Icon>
);
export const Search: React.FC<IconProps> = (p) => (
  <Icon {...p}>
    <circle cx="7" cy="7" r="4.5" />
    <path d="M10.5 10.5L13.5 13.5" />
  </Icon>
);
export const Bug: React.FC<IconProps> = (p) => (
  <Icon {...p}>
    <rect x="5" y="5" width="6" height="7" rx="3" />
    <path d="M5 8H2.5M11 8h2.5M5 11l-2 1.5M11 11l2 1.5M5 5l-1.5-1.5M11 5l1.5-1.5M8 3v2" />
  </Icon>
);
export const Folder: React.FC<IconProps> = (p) => (
  <Icon {...p}>
    <path d="M2 4.5v7a1 1 0 001 1h10a1 1 0 001-1v-6a1 1 0 00-1-1H7.5L6 3H3a1 1 0 00-1 1v.5z" />
  </Icon>
);
export const File: React.FC<IconProps> = (p) => (
  <Icon {...p}>
    <path d="M3.5 2h5.5l3.5 3.5V14a0 0 0 010 0H3.5a0 0 0 010 0V2z" />
    <path d="M9 2v3.5h3.5" />
  </Icon>
);
export const Plus: React.FC<IconProps> = (p) => (
  <Icon {...p}><path d="M8 3v10M3 8h10" /></Icon>
);
export const X: React.FC<IconProps> = (p) => (
  <Icon {...p}><path d="M3.5 3.5l9 9M12.5 3.5l-9 9" /></Icon>
);
export const Copy: React.FC<IconProps> = (p) => (
  <Icon {...p}>
    <rect x="5" y="5" width="8" height="8" rx="1.2" />
    <path d="M3 11V4.2A1.2 1.2 0 014.2 3H11" />
  </Icon>
);
export const Check: React.FC<IconProps> = (p) => (
  <Icon {...p}><path d="M3 8.5l3 3 7-7" /></Icon>
);
export const ChevronDown: React.FC<IconProps> = (p) => (
  <Icon {...p}><path d="M3.5 6L8 10.5 12.5 6" /></Icon>
);
export const ChevronRight: React.FC<IconProps> = (p) => (
  <Icon {...p}><path d="M6 3.5L10.5 8 6 12.5" /></Icon>
);
export const Filter: React.FC<IconProps> = (p) => (
  <Icon {...p}><path d="M2.5 3.5h11l-4.2 5v4l-2.6 1.2v-5.2L2.5 3.5z" /></Icon>
);
export const Refresh: React.FC<IconProps> = (p) => (
  <Icon {...p}>
    <path d="M2.5 8a5.5 5.5 0 019.4-3.9l1.6 1.6M13.5 8a5.5 5.5 0 01-9.4 3.9L2.5 10.3" />
    <path d="M13.5 2v3.7H10M2.5 14V10.3H6" />
  </Icon>
);
export const More: React.FC<IconProps> = (p) => (
  <Icon {...p}>
    <circle cx="3.5" cy="8" r="1" fill="currentColor" stroke="none" />
    <circle cx="8" cy="8" r="1" fill="currentColor" stroke="none" />
    <circle cx="12.5" cy="8" r="1" fill="currentColor" stroke="none" />
  </Icon>
);
export const Settings: React.FC<IconProps> = (p) => (
  <Icon {...p}>
    <circle cx="8" cy="8" r="2" />
    <path d="M8 1.5v2M8 12.5v2M14.5 8h-2M3.5 8h-2M12.6 3.4l-1.4 1.4M4.8 11.2l-1.4 1.4M12.6 12.6l-1.4-1.4M4.8 4.8L3.4 3.4" />
  </Icon>
);
export const Wand: React.FC<IconProps> = (p) => (
  <Icon {...p}>
    <path d="M3 13L11.5 4.5" />
    <path
      d="M10 3l1 1M13 6l1 1M5.5 12.5l1 1M2 7l1.5-.5L4 5l.5 1.5L6 7l-1.5.5L4 9l-.5-1.5L2 7zM12 9l1-.3.3-1 .3 1 1 .3-1 .3-.3 1-.3-1-1-.3z"
      fill="currentColor"
      stroke="none"
    />
  </Icon>
);
export const Lightning: React.FC<IconProps> = (p) => (
  <Icon {...p} fill="currentColor">
    <path d="M9 1L3 9h4l-1 6 6-8H8l1-6z" />
  </Icon>
);
export const AlertTriangle: React.FC<IconProps> = (p) => (
  <Icon {...p}>
    <path d="M8 2.5l6 11H2L8 2.5z" />
    <path d="M8 6.5v3.5M8 11.8v.4" />
  </Icon>
);
export const Eye: React.FC<IconProps> = (p) => (
  <Icon {...p}>
    <path d="M1.5 8s2.5-4.5 6.5-4.5S14.5 8 14.5 8s-2.5 4.5-6.5 4.5S1.5 8 1.5 8z" />
    <circle cx="8" cy="8" r="1.8" />
  </Icon>
);
export const Inbox: React.FC<IconProps> = (p) => (
  <Icon {...p}>
    <path d="M2 8.5l1.5-5h9L14 8.5v4a1 1 0 01-1 1H3a1 1 0 01-1-1v-4z" />
    <path d="M2 8.5h3.5l1 1.5h3l1-1.5H14" />
  </Icon>
);
