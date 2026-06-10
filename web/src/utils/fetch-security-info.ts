import { error } from './logger';
import { safeFetch } from './safe-fetch';
import { apiBase, enrichHeaders } from './api-config';

const normalizeRepo = (github: string): string =>
  github.replace(/^https?:\/\/github\.com\//, '').replace(/\/+$/, '');

export const fetchSecurityReport = async (
  github: string,
): Promise<SecurityReportResponse | null> => {
  const repo = normalizeRepo(github);
  const endpoint = `${apiBase}/v1/enrich/security/${repo}`;
  try {
    const res = await safeFetch(endpoint, { headers: enrichHeaders() });
    if (!res.ok) {
      error('Security Report', `HTTP ${res.status} for ${repo} (${endpoint})`);
      return null;
    }
    return await res.json();
  } catch (err) {
    error('Security Report', `Network error for ${repo}: ${err}`);
    return null;
  }
};

export interface SecurityCheck {
  name: string;
  score: number;
  reason: string;
  url: string;
}

export interface SecurityAdvisory {
  ghsaId: string;
  cveId: string | null;
  summary: string;
  severity: string;
  cvssScore: number | null;
  publishedAt: string;
  url: string;
  firstPatchedVersion: string | null;
  vulnerableRange: string;
  isPatched: boolean;
}

export interface SecurityReportResponse {
  repo: string;
  scorecard: {
    available: boolean;
    overallScore: number | null;
    generatedAt: string;
    checks: SecurityCheck[];
  };
  advisories: {
    count: number;
    items: SecurityAdvisory[];
  };
  fuzzed: boolean;
}
