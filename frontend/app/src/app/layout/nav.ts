/**
 * The ADR-0005 route table (plan §4): short, stable client routes with the
 * as-built sidebar glyphs and the real legacy screen URLs (the strangler
 * keeps legacy reachable until each F4 replacement ships).
 * Labels are i18n keys (ADR-0010) - never embedded strings.
 */
export interface NavItem {
  /** Absolute client route, basename /app (ADR-0005 / ADR-0012). */
  path: string;
  /** i18n key for the sidebar label. */
  labelKey: string;
  /** Material Symbols glyph exactly as the legacy sidebar renders it. */
  icon: string;
  /**
   * Real legacy screen URL - stays reachable until F4 replaces it.
   * Optional since ADR-0013: an F4-native surface (/topology) has no
   * legacy equivalent. The router's pending fallback requires one, so
   * a nav item without a legacyHref must be an implemented route.
   */
  legacyHref?: string;
  /** As-built: break-glass carries the error color on its icon. */
  danger?: boolean;
}

export const NAV_ITEMS: NavItem[] = [
  {
    path: '/command-center',
    labelKey: 'nav.commandCenter',
    icon: 'grid_view',
    legacyHref: '/screens/pam_command_center_threat_dashboard/code.html',
  },
  {
    path: '/vault',
    labelKey: 'nav.vault',
    icon: 'vpn_key',
    legacyHref: '/screens/credential_vault_secrets_inventory/code.html',
  },
  {
    path: '/jit',
    labelKey: 'nav.jit',
    icon: 'hourglass_top',
    legacyHref: '/screens/jit_access_ephemeral_approvals/code.html',
  },
  {
    path: '/sessions',
    labelKey: 'nav.sessions',
    icon: 'terminal',
    legacyHref: '/screens/live_session_recording_inspection_hub/code.html',
  },
  {
    path: '/infrastructure',
    labelKey: 'nav.infrastructure',
    icon: 'dns',
    legacyHref: '/screens/target_infrastructure_connectors/code.html',
  },
  {
    path: '/policy',
    labelKey: 'nav.policy',
    icon: 'shield_lock',
    legacyHref: '/screens/policy_zero_trust_rules_engine/code.html',
  },
  {
    path: '/compliance',
    labelKey: 'nav.compliance',
    icon: 'policy',
    legacyHref: '/screens/compliance_soc_2_audit_center/code.html',
  },
  {
    path: '/licensing',
    labelKey: 'nav.licensing',
    icon: 'workspace_premium',
    legacyHref: '/screens/enterprise_licensing_tier_entitlements_node_quotas/code.html',
  },
  {
    path: '/break-glass',
    labelKey: 'nav.breakGlass',
    icon: 'emergency_home',
    legacyHref: '/screens/break_glass_emergency_protocol/code.html',
    danger: true,
  },
  {
    path: '/vendor-access',
    labelKey: 'nav.vendorAccess',
    icon: 'handshake',
    legacyHref: '/screens/vendor_access_third_party_lifecycle/code.html',
  },
  {
    path: '/settings',
    labelKey: 'nav.settings',
    icon: 'tune',
    // ADR-0015: the strangle target is the page the server actually
    // served (`app.py` SETTINGS_SCREEN) and the one the legacy sidebar
    // linked to. 11.5 flipped it: the React route is live, the legacy
    // page is deleted and the server redirects /settings here - so the
    // nav item carries no legacyHref (an F4-native surface, /topology's
    // precedent).
  },
  {
    // ADR-0013: F4-native surface, no legacy screen to strangle - the
    // only nav item without a legacyHref (the pending fallback skips
    // it; the route below implements it).
    path: '/topology',
    labelKey: 'nav.topology',
    icon: 'schema',
  },
];
