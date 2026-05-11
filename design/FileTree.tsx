import * as React from "react";
import { useState } from "react";
import { ChevronDown, Folder, File } from "./icons";
import type { PanelTreeNode } from "./types";

const EXT_COLORS: Record<string, string> = {
  ts:   "#3b82f6",
  tsx:  "#3b82f6",
  js:   "#f59e0b",
  jsx:  "#f59e0b",
  mjs:  "#f59e0b",
  cjs:  "#f59e0b",
  json: "#6b7280",
  yml:  "#6b7280",
  yaml: "#6b7280",
  env:  "#10b981",
  css:  "#a78bfa",
  md:   "#64748b",
  py:   "#3b82f6",
  go:   "#22d3ee",
  rs:   "#f97316",
  rb:   "#ef4444",
  php:  "#a78bfa",
  java: "#f97316",
};

function getFileIds(nodes: PanelTreeNode[]): string[] {
  const ids: string[] = [];
  const walk = (n: PanelTreeNode): void => {
    if (n.type === "file") { ids.push(n.id); }
    n.children?.forEach(walk);
  };
  nodes.forEach(walk);
  return ids;
}

function childFileIds(node: PanelTreeNode): string[] {
  const ids: string[] = [];
  const walk = (n: PanelTreeNode): void => {
    if (n.type === "file") { ids.push(n.id); }
    n.children?.forEach(walk);
  };
  walk(node);
  return ids;
}

interface NodeProps {
  node:        PanelTreeNode;
  selected:    Set<string>;
  onToggleSelect: (node: PanelTreeNode) => void;
  openState:   Record<string, boolean>;
  onToggleOpen: (id: string, newVal: boolean) => void;
  depth?:      number;
}

const TreeNode: React.FC<NodeProps> = ({
  node,
  selected,
  onToggleSelect,
  openState,
  onToggleOpen,
  depth = 0,
}) => {
  const isOpen = openState[node.id] !== undefined ? openState[node.id] : node.open !== false;
  const fileIds = node.type === "folder" ? childFileIds(node) : [node.id];
  const selectedCount = fileIds.filter((id) => selected.has(id)).length;
  const isChecked =
    node.type === "file" ? selected.has(node.id) : fileIds.length > 0 && selectedCount === fileIds.length;
  const isIndeterminate =
    node.type === "folder" && selectedCount > 0 && selectedCount < fileIds.length;
  const extColor = (node.ext && EXT_COLORS[node.ext]) || "var(--text-faint)";

  return (
    <>
      <div
        className="vs-tree-row"
        style={{ paddingLeft: 8 + depth * 14 }}
        onClick={() => (node.type === "folder" ? onToggleOpen(node.id, !isOpen) : onToggleSelect(node))}
      >
        <span
          className={`vs-tree-check ${isChecked ? "is-checked" : ""} ${isIndeterminate ? "is-indeterminate" : ""}`}
          onClick={(e) => {
            e.stopPropagation();
            onToggleSelect(node);
          }}
        />

        {node.type === "folder" ? (
          <span
            style={{
              color: "var(--text-faint)",
              display: "inline-flex",
              transition: "transform 0.12s",
              transform: isOpen ? "none" : "rotate(-90deg)",
              flexShrink: 0,
            }}
          >
            <ChevronDown size={11} />
          </span>
        ) : (
          <span style={{ width: 11, flexShrink: 0 }} />
        )}

        <span
          style={{
            color: node.type === "folder" ? "var(--accent)" : extColor,
            display: "inline-flex",
            flexShrink: 0,
          }}
        >
          {node.type === "folder" ? <Folder size={13} /> : <File size={13} />}
        </span>

        <span
          className="vs-tree-name"
          style={node.scannable === false ? { color: "var(--text-faint)" } : undefined}
        >
          {node.name}
        </span>

        {node.type === "folder" && selectedCount > 0 && (
          <span
            style={{
              marginLeft: "auto",
              fontFamily: "var(--vs-mono)",
              fontSize: 10,
              color: "var(--accent)",
              background: "var(--accent-soft)",
              padding: "1px 5px",
              borderRadius: 999,
              flexShrink: 0,
            }}
          >
            {selectedCount}
          </span>
        )}
      </div>

      {node.type === "folder" && isOpen && node.children?.map((child) => (
        <TreeNode
          key={child.id}
          node={child}
          selected={selected}
          onToggleSelect={onToggleSelect}
          openState={openState}
          onToggleOpen={onToggleOpen}
          depth={depth + 1}
        />
      ))}
    </>
  );
};

interface FileTreeProps {
  tree:              PanelTreeNode[];
  selected:          Set<string>;
  onSelectionChange: (next: Set<string>) => void;
}

export const FileTree: React.FC<FileTreeProps> = ({ tree, selected, onSelectionChange }) => {
  const [openState, setOpenState] = useState<Record<string, boolean>>({});
  const totalFiles = getFileIds(tree).length;

  const toggleOpen = (id: string, newVal: boolean): void => {
    setOpenState((s) => ({ ...s, [id]: newVal }));
  };

  const toggleSelect = (node: PanelTreeNode): void => {
    const ids = node.type === "folder" ? childFileIds(node) : [node.id];
    if (ids.length === 0) { return; }
    const allSelected = ids.every((id) => selected.has(id));
    const next = new Set(selected);
    ids.forEach((id) => (allSelected ? next.delete(id) : next.add(id)));
    onSelectionChange(next);
  };

  const allFileIds = getFileIds(tree);
  const allSelected = allFileIds.length > 0 && allFileIds.every((id) => selected.has(id));

  return (
    <div className="vs-files" style={{ borderRadius: 6 }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 6,
          padding: "6px 10px",
          borderBottom: "1px solid var(--border-soft)",
          background: "var(--surface-2)",
        }}
      >
        <span
          className={`vs-tree-check ${allSelected ? "is-checked" : selected.size > 0 ? "is-indeterminate" : ""}`}
          onClick={() =>
            onSelectionChange(allSelected ? new Set() : new Set(allFileIds))
          }
          style={{ cursor: "pointer" }}
        />
        <span style={{ fontSize: 11, color: "var(--text-muted)", flex: 1 }}>
          {selected.size === 0
            ? totalFiles === 0
              ? "No scannable files in this workspace"
              : "Select files to analyze"
            : `${selected.size} of ${totalFiles} files selected`}
        </span>
        {selected.size > 0 && (
          <button
            className="vs-btn vs-btn-ghost"
            style={{ height: 18, padding: "0 6px", fontSize: 10.5 }}
            onClick={() => onSelectionChange(new Set())}
          >
            Clear
          </button>
        )}
      </div>

      <div style={{ paddingTop: 2, paddingBottom: 2 }}>
        {tree.map((node) => (
          <TreeNode
            key={node.id}
            node={node}
            selected={selected}
            onToggleSelect={toggleSelect}
            openState={openState}
            onToggleOpen={toggleOpen}
            depth={0}
          />
        ))}
      </div>
    </div>
  );
};
