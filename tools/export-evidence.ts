#!/usr/bin/env node

import { existsSync, mkdirSync, writeFileSync } from 'fs';
import { join } from 'path';
import { StorageService } from '../src/services/storage';
import { generateRequestId } from '../src/utils/crypto';
import type { EvidencePackage } from '../src/schemas/request';

/**
 * Evidence Export Tool for Arc Browser MITM Telemetry Observer
 * 
 * This tool exports captured telemetry data, user actions, and analysis results
 * into a structured evidence package for further analysis or compliance reporting.
 */

interface ExportOptions {
  sessionId?: string;
  outputDir?: string;
  format?: 'json' | 'csv' | 'both';
  includeRawData?: boolean;
  compress?: boolean;
}

class EvidenceExporter {
  private storage: StorageService;

  constructor(dbPath: string) {
    if (!existsSync(dbPath)) {
      throw new Error(`Database file not found: ${dbPath}`);
    }
    this.storage = new StorageService(dbPath);
  }

  /**
   * Export evidence package for a specific session or all sessions
   */
  public async exportEvidence(options: ExportOptions = {}): Promise<string> {
    const {
      sessionId,
      outputDir = join(process.cwd(), 'evidence-packages'),
      format = 'json',
      includeRawData = true,
    } = options;

    // Create output directory if it doesn't exist
    if (!existsSync(outputDir)) {
      mkdirSync(outputDir, { recursive: true });
    }

    // Get session data
    const targetSessionId = sessionId || this.getCurrentSessionId();
    if (!targetSessionId) {
      throw new Error('No session ID provided and no current session found');
    }

    const session = this.storage.getSession(targetSessionId);
    if (!session) {
      throw new Error(`Session not found: ${targetSessionId}`);
    }

    // Gather all data
    const requests = this.storage.getRequestsBySession(targetSessionId);
    const responses = this.storage.getResponsesBySession(targetSessionId);
    const userActions = this.storage.getUserActionsBySession(targetSessionId);
    const analysisResults = this.storage.getAnalysisResults(targetSessionId);
    const stats = this.storage.getSessionStats(targetSessionId);

    // Create evidence package
    const evidencePackage: EvidencePackage = {
      id: generateRequestId(),
      sessionId: targetSessionId,
      timestamp: new Date(),
      requests,
      responses,
      userActions,
      analysisResults,
      metadata: {
        osVersion: `${process.platform} ${process.version}`,
        userAgent: 'Arc-MITM-Observer/1.0.0',
        duration: stats.duration,
        exportedAt: new Date().toISOString(),
        totalRequests: stats.requestCount,
        telemetryRequests: stats.telemetryCount,
        uniqueDomains: stats.uniqueDomains,
        exportOptions: options,
      },
    };

    // Generate output filename
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const baseFilename = `arc-evidence-${targetSessionId}-${timestamp}`;

    let outputPath = '';

    // Export in requested format(s)
    if (format === 'json' || format === 'both') {
      const jsonPath = join(outputDir, `${baseFilename}.json`);
      writeFileSync(jsonPath, JSON.stringify(evidencePackage, null, 2));
      outputPath = jsonPath;
      console.log(`✅ JSON evidence package exported: ${jsonPath}`);
    }

    if (format === 'csv' || format === 'both') {
      const csvDir = join(outputDir, baseFilename);
      mkdirSync(csvDir, { recursive: true });
      
      // Export requests as CSV
      this.exportRequestsToCSV(requests, join(csvDir, 'requests.csv'));
      
      // Export responses as CSV
      this.exportResponsesToCSV(responses, join(csvDir, 'responses.csv'));
      
      // Export user actions as CSV
      this.exportUserActionsToCSV(userActions, join(csvDir, 'user-actions.csv'));
      
      // Export analysis results as CSV
      this.exportAnalysisResultsToCSV(analysisResults, join(csvDir, 'analysis-results.csv'));
      
      // Export summary as CSV
      this.exportSummaryToCSV(evidencePackage, join(csvDir, 'summary.csv'));
      
      outputPath = csvDir;
      console.log(`✅ CSV evidence package exported: ${csvDir}`);
    }

    // Generate analysis summary
    this.printAnalysisSummary(evidencePackage);

    return outputPath;
  }

  /**
   * Export requests to CSV format
   */
  private exportRequestsToCSV(requests: any[], filePath: string): void {
    const headers = [
      'ID', 'Timestamp', 'Method', 'URL', 'Domain', 'User-Agent', 'Origin',
      'Content-Type', 'Content-Length', 'Has-Body'
    ];

    const rows = requests.map(req => [
      req.id,
      req.timestamp.toISOString(),
      req.method,
      req.url,
      this.extractDomain(req.url),
      req.userAgent || '',
      req.origin || '',
      req.headers['content-type'] || '',
      req.headers['content-length'] || '',
      req.body ? 'Yes' : 'No'
    ]);

    this.writeCSV(filePath, headers, rows);
  }

  /**
   * Export responses to CSV format
   */
  private exportResponsesToCSV(responses: any[], filePath: string): void {
    const headers = [
      'ID', 'Request-ID', 'Timestamp', 'Status', 'Status-Text', 'Response-Time',
      'Content-Type', 'Content-Length', 'Has-Body'
    ];

    const rows = responses.map(res => [
      res.id,
      res.requestId,
      res.timestamp.toISOString(),
      res.status.toString(),
      res.statusText,
      res.responseTime.toString(),
      res.headers['content-type'] || '',
      res.headers['content-length'] || '',
      res.body ? 'Yes' : 'No'
    ]);

    this.writeCSV(filePath, headers, rows);
  }

  /**
   * Export user actions to CSV format
   */
  private exportUserActionsToCSV(userActions: any[], filePath: string): void {
    const headers = ['ID', 'Timestamp', 'Action', 'Description', 'Metadata'];

    const rows = userActions.map(action => [
      action.id,
      action.timestamp.toISOString(),
      action.action,
      action.description || '',
      JSON.stringify(action.metadata || {})
    ]);

    this.writeCSV(filePath, headers, rows);
  }

  /**
   * Export analysis results to CSV format
   */
  private exportAnalysisResultsToCSV(analysisResults: any[], filePath: string): void {
    const headers = ['ID', 'Timestamp', 'Type', 'Severity', 'Description', 'Evidence'];

    const rows = analysisResults.map(result => [
      result.id,
      result.timestamp.toISOString(),
      result.type,
      result.severity,
      result.description,
      JSON.stringify(result.evidence)
    ]);

    this.writeCSV(filePath, headers, rows);
  }

  /**
   * Export summary information to CSV format
   */
  private exportSummaryToCSV(evidencePackage: EvidencePackage, filePath: string): void {
    const headers = ['Metric', 'Value'];
    const metadata = evidencePackage.metadata;

    const rows = [
      ['Session ID', evidencePackage.sessionId],
      ['Export Timestamp', evidencePackage.timestamp.toISOString()],
      ['Duration (ms)', metadata.duration.toString()],
      ['Total Requests', metadata.totalRequests?.toString() || '0'],
      ['Telemetry Requests', metadata.telemetryRequests?.toString() || '0'],
      ['Unique Domains', metadata.uniqueDomains?.toString() || '0'],
      ['User Actions', evidencePackage.userActions.length.toString()],
      ['Analysis Results', evidencePackage.analysisResults.length.toString()],
      ['OS Version', metadata.osVersion],
      ['User Agent', metadata.userAgent],
    ];

    this.writeCSV(filePath, headers, rows);
  }

  /**
   * Write data to CSV file
   */
  private writeCSV(filePath: string, headers: string[], rows: string[][]): void {
    const csvContent = [
      headers.join(','),
      ...rows.map(row => row.map(cell => `"${cell.replace(/"/g, '""')}"`).join(','))
    ].join('\n');

    writeFileSync(filePath, csvContent);
  }

  /**
   * Print analysis summary to console
   */
  private printAnalysisSummary(evidencePackage: EvidencePackage): void {
    const { requests, responses, userActions, analysisResults, metadata } = evidencePackage;

    console.log('\n📊 Evidence Package Summary');
    console.log('═'.repeat(50));
    console.log(`Session ID: ${evidencePackage.sessionId}`);
    console.log(`Export Time: ${evidencePackage.timestamp.toISOString()}`);
    console.log(`Duration: ${Math.round(metadata.duration / 1000)} seconds`);
    console.log('');

    console.log('📈 Traffic Statistics:');
    console.log(`  Total Requests: ${requests.length}`);
    console.log(`  Total Responses: ${responses.length}`);
    console.log(`  Telemetry Requests: ${metadata.telemetryRequests || 0}`);
    console.log(`  Unique Domains: ${metadata.uniqueDomains || 0}`);
    console.log(`  User Actions: ${userActions.length}`);
    console.log('');

    // Analyze telemetry domains
    const telemetryDomains = this.getTelemetryDomains(requests);
    if (telemetryDomains.length > 0) {
      console.log('🎯 Telemetry Domains Detected:');
      telemetryDomains.forEach(domain => {
        console.log(`  - ${domain.domain} (${domain.count} requests)`);
      });
      console.log('');
    }

    // Analyze privacy violations
    if (analysisResults.length > 0) {
      console.log('🚨 Privacy Analysis Results:');
      const violations = this.groupAnalysisResults(analysisResults);
      
      Object.entries(violations).forEach(([type, severities]) => {
        const total = Object.values(severities).reduce((sum, count) => sum + count, 0);
        console.log(`  ${type}: ${total} issues`);
        
        Object.entries(severities).forEach(([severity, count]) => {
          const emoji = this.getSeverityEmoji(severity);
          console.log(`    ${emoji} ${severity}: ${count}`);
        });
      });
      console.log('');
    } else {
      console.log('✅ No privacy violations detected');
      console.log('');
    }

    console.log('📋 Next Steps:');
    console.log('  1. Review the exported evidence files');
    console.log('  2. Analyze telemetry patterns for privacy violations');
    console.log('  3. Correlate user actions with network requests');
    console.log('  4. Generate compliance reports if needed');
    console.log('');
  }

  /**
   * Get telemetry domains from requests
   */
  private getTelemetryDomains(requests: any[]): Array<{ domain: string; count: number }> {
    const domainCounts: Record<string, number> = {};
    
    requests.forEach(req => {
      const domain = this.extractDomain(req.url);
      if (this.isTelemetryDomain(domain)) {
        domainCounts[domain] = (domainCounts[domain] || 0) + 1;
      }
    });

    return Object.entries(domainCounts)
      .map(([domain, count]) => ({ domain, count }))
      .sort((a, b) => b.count - a.count);
  }

  /**
   * Group analysis results by type and severity
   */
  private groupAnalysisResults(analysisResults: any[]): Record<string, Record<string, number>> {
    const grouped: Record<string, Record<string, number>> = {};

    analysisResults.forEach(result => {
      if (!grouped[result.type]) grouped[result.type] = {};
      if (!grouped[result.type][result.severity]) grouped[result.type][result.severity] = 0;
      grouped[result.type][result.severity]++;
    });

    return grouped;
  }

  /**
   * Get emoji for severity level
   */
  private getSeverityEmoji(severity: string): string {
    const emojiMap: Record<string, string> = {
      low: '💙',
      medium: '💛',
      high: '🧡',
      critical: '❤️',
    };
    return emojiMap[severity] || '❓';
  }

  /**
   * Extract domain from URL
   */
  private extractDomain(url: string): string {
    try {
      return new URL(url).hostname;
    } catch {
      return '';
    }
  }

  /**
   * Check if domain is a known telemetry domain
   */
  private isTelemetryDomain(domain: string): boolean {
    const telemetryDomains = [
      'api.segment.io',
      'firebaseio.com',
      'amplitude.com',
      'sentry.io',
      'launchdarkly.com',
      'telemetry.arc.net',
      'analytics.arc.net',
      'api.mixpanel.com',
      'track.customer.io',
      'api.intercom.io',
    ];

    return telemetryDomains.some(td => domain === td || domain.endsWith(`.${td}`));
  }

  /**
   * Get the most recent session ID
   */
  private getCurrentSessionId(): string | null {
    // This would need to be implemented based on how sessions are tracked
    // For now, return null to force explicit session ID
    return null;
  }

  /**
   * Cleanup resources
   */
  public cleanup(): void {
    this.storage.close();
  }
}

// CLI Interface
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  
  // Parse command line arguments
  const options: ExportOptions = {};
  let dbPath = join(process.cwd(), 'logs', 'telemetry.db');

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    
    switch (arg) {
      case '--session':
      case '-s':
        options.sessionId = args[++i];
        break;
      case '--output':
      case '-o':
        options.outputDir = args[++i];
        break;
      case '--format':
      case '-f':
        options.format = args[++i] as 'json' | 'csv' | 'both';
        break;
      case '--db':
        dbPath = args[++i];
        break;
      case '--help':
      case '-h':
        printHelp();
        process.exit(0);
        break;
      default:
        if (!arg.startsWith('-')) {
          options.sessionId = arg;
        }
        break;
    }
  }

  try {
    console.log('🚀 Starting evidence export...');
    console.log(`📂 Database: ${dbPath}`);
    
    const exporter = new EvidenceExporter(dbPath);
    const outputPath = await exporter.exportEvidence(options);
    
    console.log(`🎉 Evidence export completed successfully!`);
    console.log(`📁 Output: ${outputPath}`);
    
    exporter.cleanup();
    
  } catch (error) {
    console.error('❌ Export failed:', (error as Error).message);
    process.exit(1);
  }
}

function printHelp(): void {
  console.log(`
Arc Browser MITM Telemetry Observer - Evidence Export Tool

Usage: node export-evidence.js [options] [sessionId]

Options:
  -s, --session <id>     Session ID to export (if not provided, uses latest)
  -o, --output <dir>     Output directory (default: ./evidence-packages)
  -f, --format <format>  Export format: json, csv, or both (default: json)
  --db <path>           Database file path (default: ./logs/telemetry.db)
  -h, --help            Show this help message

Examples:
  node export-evidence.js                          # Export latest session as JSON
  node export-evidence.js abc-123-def             # Export specific session
  node export-evidence.js -f csv -o ./exports     # Export as CSV to custom directory
  node export-evidence.js -f both                 # Export in both JSON and CSV formats

Note: This tool is for defensive security research only. Only export data from
your own devices and traffic.
`);
}

// Run CLI if this file is executed directly
if (require.main === module) {
  main().catch(console.error);
}

export { EvidenceExporter, type ExportOptions };