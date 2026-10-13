import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

import en from './en.json';

/**
 * ADR-0010: English first, one catalogue (`en.json`), components never
 * embed user-facing strings from F3 on. `hi.json` lands in a later pass -
 * the wiring already exists so Hindi costs translations only.
 */
i18n.use(initReactI18next).init({
  lng: 'en',
  fallbackLng: 'en',
  resources: {
    en: { translation: en },
  },
  interpolation: {
    escapeValue: false, // React escapes already
  },
  returnNull: false,
});

export default i18n;
