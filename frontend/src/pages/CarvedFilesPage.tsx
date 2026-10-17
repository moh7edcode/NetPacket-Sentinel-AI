import { useTranslation } from "react-i18next";
import { useQuery } from "@tanstack/react-query";
import { Download, FileSearch, HardDrive } from "lucide-react";
import { api } from "@/services/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { PageHeader } from "@/components/layout/PageHeader";
import { formatBytes } from "@/lib/utils";

export default function CarvedFilesPage() {
  const { t } = useTranslation();
  const { data: files } = useQuery({ queryKey: ["carved"], queryFn: api.carved });

  if (!files?.length) {
    return (
      <Card className="mx-auto max-w-md">
        <CardContent className="flex flex-col items-center gap-2 py-10 text-muted-foreground">
          <FileSearch className="h-8 w-8" />
          {t("carved_page.empty")}
        </CardContent>
      </Card>
    );
  }

  return (
    <div>
      <PageHeader icon={FileSearch} title={t("nav.carved")} count={files.length} />
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {files.map((f) => (
          <Card key={f.File_ID}>
            <CardContent className="space-y-2 p-4">
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-2 text-sm font-semibold">
                  <HardDrive className="h-4 w-4 text-primary" />
                  {f.Filename}
                </span>
                <span className="mono text-[10px] uppercase text-muted-foreground">{f.File_Type}</span>
              </div>
              <div className="mono text-[11px] text-muted-foreground">
                {f.Source_IP} → {f.Dest_IP} · {f.Protocol} · {formatBytes(f.Size_Bytes)}
              </div>
              <div className="space-y-0.5">
                <div className="mono break-all text-[9px] text-muted-foreground" title={f.SHA256}>
                  SHA256: {f.SHA256?.slice(0, 40)}…
                </div>
                <div className="mono break-all text-[9px] text-muted-foreground" title={f.MD5}>
                  MD5: {f.MD5}
                </div>
              </div>
              <Button asChild size="sm" variant="outline" className="w-full">
                <a href={api.downloadCarvedUrl(f.File_ID)} download={f.Filename}>
                  <Download className="h-3.5 w-3.5" /> {t("carved_page.download")}
                </a>
              </Button>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
