/**
 * Scan Profiles Configuration
 */

import { TIER_1_MODULES, TIER_2_MODULES, TIER_3_MODULES } from '../modules/tierConfig.js';

export type ScanProfile = 'full' | 'quick' | 'wordpress' | 'infostealer' | 'email';

export interface ProfileConfig {
  name: ScanProfile;
  description: string;
  modules: string[];
  estimatedDuration: string;
}

export const SCAN_PROFILES: Record<ScanProfile, ProfileConfig> = {
  full: {
    name: 'full',
    description: 'Complete security scan with all 20 modules',
    modules: [...TIER_1_MODULES, ...TIER_2_MODULES, ...TIER_3_MODULES],
    estimatedDuration: '5-10 minutes'
  },
  quick: {
    name: 'quick',
    description: 'Fast reconnaissance scan',
    modules: ['tech_stack_scan', 'tls_scan', 'shodan', 'spf_dmarc'],
    estimatedDuration: '2-3 minutes'
  },
  wordpress: {
    name: 'wordpress',
    description: 'WordPress-focused scan',
    modules: ['wp_plugin_quickscan', 'tech_stack_scan', 'tls_scan', 'config_exposure', 'admin_panel_detector'],
    estimatedDuration: '3-5 minutes'
  },
  infostealer: {
    name: 'infostealer',
    description: 'Credential exposure scan',
    modules: ['infostealer_probe', 'client_secret_scanner', 'config_exposure'],
    estimatedDuration: '2-3 minutes'
  },
  email: {
    name: 'email',
    description: 'Email security scan',
    modules: ['spf_dmarc', 'dns_zone_transfer'],
    estimatedDuration: '1-2 minutes'
  }
};

export function getProfileModules(profile: ScanProfile): string[] {
  return SCAN_PROFILES[profile]?.modules || SCAN_PROFILES.full.modules;
}

export function isValidProfile(profile: string): profile is ScanProfile {
  return profile in SCAN_PROFILES;
}

export default { SCAN_PROFILES, getProfileModules, isValidProfile };
