import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { projectsApi } from '@/api/client';
import { Button } from '@/components/ui/button';
import { Dialog } from '@/components/ui/dialog';
import { Field, Input, Textarea } from '@/components/ui/input';
import { useToast } from '@/components/ui/toast';
import { parseTags } from '@/lib/utils';
import type { CloneInput, Project } from '@/lib/types';

export function NewProjectDialog({
  open,
  onClose,
  onCreated,
}: {
  open: boolean;
  onClose: () => void;
  onCreated?: (p: Project) => void;
}) {
  const toast = useToast();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [tags, setTags] = useState('');
  const [busy, setBusy] = useState(false);

  const create = async () => {
    if (!name.trim()) return;
    setBusy(true);
    try {
      const p = await projectsApi.create({
        name: name.trim(),
        description: description.trim() || undefined,
        tags: parseTags(tags).length ? parseTags(tags) : undefined,
      });
      toast.success(`Project “${p.name}” created 🎉`);
      setName('');
      setDescription('');
      setTags('');
      onCreated?.(p);
      onClose();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to create project');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="📁 New Project"
      description="A project is an assessment scope — targets, assets, findings and scans live here."
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" onClick={create} loading={busy} disabled={!name.trim()}>
            Create project
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label="Name" required>
          <Input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Acme Corp external pentest"
            onKeyDown={(e) => e.key === 'Enter' && create()}
          />
        </Field>
        <Field label="Description">
          <Textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="What is in scope, and why?"
          />
        </Field>
        <Field label="Tags" hint="comma separated">
          <Input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="external, q1, api" />
        </Field>
      </div>
    </Dialog>
  );
}

const CLONE_CHECKLIST: Array<{ key: 'copy_settings' | 'copy_targets' | 'copy_scanner_configs' | 'copy_profiles' | 'copy_tags' | 'copy_report_prefs'; label: string; emoji: string }> = [
  { key: 'copy_settings', label: 'Project settings', emoji: '⚙️' },
  { key: 'copy_targets', label: 'Authorized & excluded targets', emoji: '🎯' },
  { key: 'copy_scanner_configs', label: 'Scanner configs', emoji: '🔧' },
  { key: 'copy_profiles', label: 'Scan profiles', emoji: '📋' },
  { key: 'copy_tags', label: 'Tags', emoji: '🏷️' },
  { key: 'copy_report_prefs', label: 'Report preferences', emoji: '📄' },
];

export function CloneProjectDialog({
  open,
  onClose,
  source,
  onCloned,
}: {
  open: boolean;
  onClose: () => void;
  source: Project | null;
  onCloned?: (p: Project) => void;
}) {
  const toast = useToast();
  const navigate = useNavigate();
  const [name, setName] = useState('');
  const [copy, setCopy] = useState<Record<string, boolean>>(
    Object.fromEntries(CLONE_CHECKLIST.map((c) => [c.key, true])),
  );
  const [busy, setBusy] = useState(false);

  if (!source) return null;

  const clone = async () => {
    setBusy(true);
    try {
      const payload: CloneInput = { name: name.trim() || undefined };
      for (const c of CLONE_CHECKLIST) payload[c.key] = copy[c.key] ?? true;
      const p = await projectsApi.clone(source.id, payload);
      toast.success(`Cloned into “${p.name}”`);
      onCloned?.(p);
      onClose();
      navigate(`/projects/${p.id}`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Clone failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={`Clone “${source.name}”`}
      description="Pick exactly what the twin should inherit."
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" onClick={clone} loading={busy}>
            Clone project
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label="New name" hint="leave empty to auto-name">
          <Input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={`${source.name} (copy)`}
          />
        </Field>
        <div>
          <p className="mb-2 text-[13px] font-medium text-mute">Copy checklist</p>
          <ul className="space-y-1.5">
            {CLONE_CHECKLIST.map((item) => (
              <li key={item.key}>
                <label className="flex cursor-pointer items-center gap-2.5 rounded-xl border border-line/70 bg-panel/50 px-3 py-2 text-[13.5px] transition-colors hover:border-line">
                  <input
                    type="checkbox"
                    checked={copy[item.key] ?? true}
                    onChange={(e) => setCopy((c) => ({ ...c, [item.key]: e.target.checked }))}
                    className="h-4 w-4 accent-accent"
                  />
                  <span aria-hidden>{item.emoji}</span>
                  {item.label}
                </label>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </Dialog>
  );
}
