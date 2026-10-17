import { useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useTheme } from "next-themes";
import { toast } from "sonner";
import { KeyRound, Languages, Moon, Sun, Upload } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/services/api";
import { useJob } from "@/hooks/JobProvider";
import { useUpload } from "@/hooks/useAnalysis";

export function TopBar() {
  const { t, i18n } = useTranslation();
  const { theme, setTheme } = useTheme();
  const { setJobId } = useJob();
  const fileRef = useRef<HTMLInputElement>(null);
  const upload = useUpload();
  const [vtOpen, setVtOpen] = useState(false);
  const [vtKey, setVtKey] = useState("");

  const toggleLang = () => {
    const next = i18n.language === "ar" ? "en" : "ar";
    i18n.changeLanguage(next);
  };

  const onFile = (f: File | undefined) => {
    if (!f) return;
    upload.mutate(f, {
      onSuccess: (d) => {
        setJobId(d.job_id);
        toast.success(`Analyzing ${f.name}`);
      },
      onError: (e) => toast.error(String(e)),
    });
  };

  const saveKey = async () => {
    await api.setVtKey(vtKey.trim());
    toast.success(t("topbar.vt_key_saved"));
    setVtOpen(false);
  };

  return (
    <header className="flex h-14 items-center justify-end gap-2 border-b bg-card/60 px-4 backdrop-blur">
      <input
        ref={fileRef}
        type="file"
        accept=".pcap,.pcapng"
        className="hidden"
        onChange={(e) => onFile(e.target.files?.[0])}
      />
      <Button variant="outline" size="sm" onClick={() => fileRef.current?.click()} disabled={upload.isPending}>
        <Upload className="h-4 w-4" />
        {upload.isPending ? t("topbar.analyzing") : t("topbar.upload")}
      </Button>
      <Dialog open={vtOpen} onOpenChange={(o) => {
        setVtOpen(o);
        if (o) api.vtKey().then((d) => setVtKey(d.api_key)).catch(() => {});
      }}>
        <DialogTrigger asChild>
          <Button variant="ghost" size="icon" title={t("topbar.vt_key")}>
            <KeyRound className="h-4 w-4" />
          </Button>
        </DialogTrigger>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>{t("topbar.vt_key")}</DialogTitle>
          </DialogHeader>
          <div className="space-y-2">
            <Label htmlFor="vt">{t("topbar.vt_key_hint")}</Label>
            <Input id="vt" value={vtKey} onChange={(e) => setVtKey(e.target.value)} placeholder="VirusTotal API v3 key" />
            <Button onClick={saveKey} className="w-full">
              {t("topbar.vt_key")}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
      <Button variant="ghost" size="sm" onClick={toggleLang} title={t("topbar.language")}>
        <Languages className="h-4 w-4" />
        {i18n.language === "ar" ? "EN" : "عربي"}
      </Button>
      <Button
        variant="ghost"
        size="icon"
        onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
        title={theme === "dark" ? t("topbar.theme_dark") : t("topbar.theme_light")}
      >
        {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
      </Button>
    </header>
  );
}
