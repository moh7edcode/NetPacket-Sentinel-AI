import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import en from "./en.json";
import ar from "./ar.json";

i18n.use(initReactI18next).init({
  resources: {
    en: { translation: en },
    ar: { translation: ar },
  },
  lng: localStorage.getItem("app_lang") ?? "en",
  fallbackLng: "en",
  interpolation: { escapeValue: false },
});

export function applyDirection(lang: "en" | "ar") {
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
}

applyDirection((i18n.language as "en" | "ar") ?? "en");
i18n.on("languageChanged", (lng) => {
  localStorage.setItem("app_lang", lng === "ar" ? "ar" : "en");
  applyDirection(lng === "ar" ? "ar" : "en");
});

export default i18n;
