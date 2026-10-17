import { useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Inbox, PlayCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { api } from "@/services/api";
import { useJob } from "@/hooks/JobProvider";
import { useLoadPreset, useProgress, useUpload } from "@/hooks/useAnalysis";

export function UploadZone({ pct, label }: { pct: number; label: string }) {
  const { t } = useTranslation();
  const inputRef = useRef<HTMLInputElement>(null);
  const upload = useUpload();
  const preset = useLoadPreset();
  const { setJobId } = useJob();
  const qc = useQueryClient();
  const [drag, setDrag] = useState(false);

  const presets = useQuery({ queryKey: ["presets"], queryFn: api.presets });

  const handleFile = (f?: File) => {
    if (!f) return;
    upload.mutate(f, {
      onSuccess: (d) => {
        setJobId(d.job_id);
        toast.success(`Uploading ${f.name} — pipeline started`);
      },
      onError: (e) => toast.error(String(e)),
    });
  };

  const loadPreset = (id: string, name: string) => {
    preset.mutate(id, {
      onSuccess: (d) => {
        setJobId(d.job_id);
        qc.invalidateQueries({ queryKey: ["session"] });
        toast.success(`${t("upload.preset_loaded")}: ${name}`);
      },
      onError: (e) => toast.error(String(e)),
    });
  };

  return (
    <div className="mx-auto mt-10 max-w-3xl space-y-4">
      <Card
        onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
        onDragLeave={() => setDrag(false)}
        onDrop={(e) => { e.preventDefault(); setDrag(false); handleFile(e.dataTransfer.files?.[0]); }}
        className={drag ? "border-primary shadow-neon" : ""}
      >
        <CardContent className="flex flex-col items-center gap-3 py-10">
          <input ref={inputRef} type="file" accept=".pcap,.pcapng" className="hidden"
            onChange={(e) => handleFile(e.target.files?.[0])} />
          <Inbox className="h-10 w-10 text-primary" />
          <div className="text-center">
            <div className="font-display text-lg font-bold">{t("upload.title")}</div>
            <div className="text-sm text-muted-foreground">{t("upload.drop")}</div>
          </div>
          <Button variant="outline" onClick={() => inputRef.current?.click()} disabled={upload.isPending}>
            {upload.isPending ? t("upload.busy") : t("topbar.upload")}
          </Button>
          {pct > 0 && pct < 100 && (
            <div className="w-2/3 space-y-1">
              <Progress value={pct} indicatorClassName="bg-cyan-500" />
              <div className="mono text-[11px] text-muted-foreground">{label}</div>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2"><PlayCircle className="h-4 w-4 text-primary" />{t("upload.presets")}</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-2 sm:grid-cols-2">
          {(presets.data?.presets ?? []).map((p) => (
            <Button key={p.id} variant="secondary" className="justify-start text-xs"
              onClick={() => loadPreset(p.id, p.name)} disabled={preset.isPending}>
              <PlayCircle className="me-1 h-3.5 w-3.5 text-primary" />
              {p.name}
            </Button>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

// re-export hook so pages can consume progress without importing hooks directly
export { useProgress };
