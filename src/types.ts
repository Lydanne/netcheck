export interface ConnectivityResult {
  is_reachable: boolean;
  response_time_ms: number;
  status_code?: number;
  error?: string;
}

export interface DnsResult {
  a_records: string[];
  aaaa_records: string[];
  ns_records: string[];
  mx_records: string[];
  txt_records: string[];
  error?: string;
}

export interface CertificateInfo {
  subject: string;
  issuer: string;
  valid_from: number;
  valid_until: number;
  serial_number: string;
  version: number;
  error?: string;
}
