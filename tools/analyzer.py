#!/usr/bin/env python3
"""
HTTP Request Smuggling Log Analyzer
Author: dw0rf
Date: May 14, 2025

This tool analyzes logs from the frontend and backend servers to detect
HTTP Request Smuggling vulnerabilities and visualize the attack flow.
"""

import argparse
import re
import json
import glob
import os
import sys
from datetime import datetime, timedelta
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import track
import matplotlib.pyplot as plt
from matplotlib.dates import DateFormatter
import numpy as np
import pandas as pd

console = Console()

class LogAnalyzer:
    """Analyze logs from multiple servers to detect HTTP Request Smuggling"""
    
    def __init__(self, frontend_logs=None, backend_logs=None):
        self.frontend_logs = frontend_logs or []
        self.backend_logs = backend_logs or []
        self.findings = []
        self.requests = {
            'frontend': [],
            'backend': []
        }
        
    def add_frontend_log(self, log_path):
        """Add a frontend log file to analyze"""
        if os.path.exists(log_path):
            self.frontend_logs.append(log_path)
        else:
            console.print(f"[red]Warning: Frontend log file not found: {log_path}[/red]")
    
    def add_backend_log(self, log_path):
        """Add a backend log file to analyze"""
        if os.path.exists(log_path):
            self.backend_logs.append(log_path)
        else:
            console.print(f"[red]Warning: Backend log file not found: {log_path}[/red]")
    
    def analyze_nginx_log(self, log_path):
        """Parse and analyze an NGINX log file (frontend)"""
        console.print(f"[cyan]Analyzing NGINX log: {log_path}[/cyan]")
        
        # Regular expression for the detailed log format
        log_pattern = re.compile(
            r'(?P<ip>\S+) - (?P<user>\S+) \[(?P<timestamp>.*?)\] "(?P<request>.*?)" '
            r'(?P<status>\d+) (?P<bytes>\d+) "(?P<referer>.*?)" "(?P<agent>.*?)" '
            r'rt=(?P<request_time>\S+) uct="(?P<upstream_connect_time>\S*)" '
            r'uht="(?P<upstream_header_time>\S*)" urt="(?P<upstream_response_time>\S*)" '
            r'cl=(?P<content_length>\S*) te=(?P<transfer_encoding>\S*)'
        )
        
        requests = []
        
        try:
            with open(log_path, 'r') as f:
                for line in track(f, description="Parsing NGINX logs..."):
                    match = log_pattern.match(line)
                    if match:
                        data = match.groupdict()
                        
                        # Extract the request method, path, and HTTP version
                        request_parts = data['request'].split()
                        if len(request_parts) >= 3:
                            method, path, http_version = request_parts[:3]
                        else:
                            method, path, http_version = data['request'], '', ''
                        
                        # Create a standardized request object
                        request = {
                            'timestamp': data['timestamp'],
                            'ip': data['ip'],
                            'server': 'frontend',
                            'method': method,
                            'path': path,
                            'http_version': http_version,
                            'status': data['status'],
                            'content_length': data['content_length'],
                            'transfer_encoding': data['transfer_encoding'],
                            'request_time': float(data['request_time']) if data['request_time'] != '-' else 0,
                            'upstream_time': float(data['upstream_response_time']) if data['upstream_response_time'] != '-' else 0,
                            'raw_log': line
                        }
                        
                        requests.append(request)
                        
                        # Check for potential smuggling indicators
                        if (data['content_length'] != '-' and data['transfer_encoding'] != '-') or \
                           ('chunked' in line and 'Content-Length' in line):
                            self.findings.append({
                                'type': 'Potential Request Smuggling',
                                'server': 'frontend',
                                'timestamp': data['timestamp'],
                                'ip': data['ip'],
                                'request': data['request'],
                                'content_length': data['content_length'],
                                'transfer_encoding': data['transfer_encoding'],
                                'raw_log': line
                            })
        except Exception as e:
            console.print(f"[bold red]Error parsing NGINX log {log_path}: {str(e)}[/bold red]")
        
        return requests
    
    def analyze_nodejs_log(self, log_path):
        """Parse and analyze a Node.js log file (backend)"""
        console.print(f"[cyan]Analyzing Node.js log: {log_path}[/cyan]")
        
        requests = []
        
        try:
            with open(log_path, 'r') as f:
                for line in track(f, description="Parsing Node.js logs..."):
                    try:
                        # Attempt to parse as JSON (Winston logger format)
                        data = json.loads(line)
                        
                        # Check if this is a request log entry
                        if 'message' in data and 'Incoming request' in data.get('message', ''):
                            # Extract request data
                            timestamp = data.get('timestamp', '')
                            method = data.get('method', '')
                            url = data.get('url', '')
                            headers = data.get('headers', {})
                            
                            # Create a standardized request object
                            request = {
                                'timestamp': timestamp,
                                'ip': data.get('ip', ''),
                                'server': 'backend',
                                'method': method,
                                'path': url,
                                'http_version': headers.get('http_version', ''),
                                'status': 0,  # Will be updated when response is found
                                'content_length': headers.get('content-length', ''),
                                'transfer_encoding': headers.get('transfer-encoding', ''),
                                'raw_log': line
                            }
                            
                            requests.append(request)
                            
                            # Check for potential smuggling indicators
                            if ('content-length' in headers and 'transfer-encoding' in headers) or \
                               (request.get('rawBody', '') and len(request.get('rawBody', '')) > 0 and 
                                'chunked' in str(headers)):
                                self.findings.append({
                                    'type': 'Potential Request Smuggling',
                                    'server': 'backend',
                                    'timestamp': timestamp,
                                    'ip': data.get('ip', ''),
                                    'request': f"{method} {url}",
                                    'content_length': headers.get('content-length', ''),
                                    'transfer_encoding': headers.get('transfer-encoding', ''),
                                    'raw_log': line
                                })
                    except json.JSONDecodeError:
                        # Not a JSON line, could be plain text or another format
                        # We could implement other parsers here if needed
                        pass
        except Exception as e:
            console.print(f"[bold red]Error parsing Node.js log {log_path}: {str(e)}[/bold red]")
        
        return requests
    
    def analyze_access_denied_patterns(self):
        """Look for patterns of access denied responses that might indicate successful smuggling"""
        admin_access_attempts = []
        
        # First, gather all admin access attempts
        for server_type, requests in self.requests.items():
            for req in requests:
                if '/admin' in req.get('path', '') or req.get('status') == '403':
                    admin_access_attempts.append(req)
        
        # Sort by timestamp
        admin_access_attempts.sort(key=lambda x: x.get('timestamp', ''))
        
        # Look for clusters of admin access attempts
        if len(admin_access_attempts) > 1:
            for i in range(len(admin_access_attempts) - 1):
                current = admin_access_attempts[i]
                next_req = admin_access_attempts[i + 1]
                
                # If there are two admin requests within a short time window from the same IP
                # but one is on the frontend and one is on the backend, this could indicate smuggling
                current_time = datetime.strptime(current.get('timestamp', ''), '%d/%b/%Y:%H:%M:%S %z')
                next_time = datetime.strptime(next_req.get('timestamp', ''), '%d/%b/%Y:%H:%M:%S %z')
                
                time_diff = (next_time - current_time).total_seconds()
                
                if time_diff < 2 and current.get('server') != next_req.get('server'):
                    self.findings.append({
                        'type': 'Possible Successful Smuggling',
                        'evidence': 'Admin access attempts on different servers within 2 seconds',
                        'first_request': current,
                        'second_request': next_req,
                        'time_difference': time_diff
                    })
    
    def analyze_timing_anomalies(self):
        """Look for timing anomalies that might indicate request smuggling"""
        for server_type, requests in self.requests.items():
            # Calculate average request time
            request_times = [req.get('request_time', 0) for req in requests if req.get('request_time', 0) > 0]
            if not request_times:
                continue
                
            avg_time = sum(request_times) / len(request_times)
            std_dev = np.std(request_times)
            
            # Look for requests that took significantly longer than average
            for req in requests:
                if req.get('request_time', 0) > avg_time + 3 * std_dev:
                    self.findings.append({
                        'type': 'Timing Anomaly',
                        'server': server_type,
                        'timestamp': req.get('timestamp', ''),
                        'ip': req.get('ip', ''),
                        'request': f"{req.get('method', '')} {req.get('path', '')}",
                        'request_time': req.get('request_time', 0),
                        'avg_request_time': avg_time,
                        'std_dev': std_dev,
                        'raw_log': req.get('raw_log', '')
                    })

    def analyze_header_anomalies(self):
        """Analyze for headers that might indicate smuggling vulnerabilities"""
        for server_type, requests in self.requests.items():
            for req in requests:
                content_length = req.get('content_length', '')
                transfer_encoding = req.get('transfer_encoding', '')
                
                # If both Content-Length and Transfer-Encoding are present
                if content_length and transfer_encoding and transfer_encoding != '-':
                    self.findings.append({
                        'type': 'Conflicting Headers',
                        'server': server_type,
                        'timestamp': req.get('timestamp', ''),
                        'ip': req.get('ip', ''),
                        'request': f"{req.get('method', '')} {req.get('path', '')}",
                        'content_length': content_length,
                        'transfer_encoding': transfer_encoding,
                        'raw_log': req.get('raw_log', '')
                    })
    
    def correlate_frontend_backend_requests(self):
        """
        Correlate frontend and backend requests to identify discrepancies
        that might indicate request smuggling
        """
        # Group requests by timestamp (rounded to the nearest second)
        frontend_by_time = {}
        backend_by_time = {}
        
        for req in self.requests['frontend']:
            try:
                # Parse timestamp and round to the nearest second
                ts = datetime.strptime(req.get('timestamp', ''), '%d/%b/%Y:%H:%M:%S %z')
                ts_key = ts.strftime('%Y-%m-%d %H:%M:%S')
                
                if ts_key not in frontend_by_time:
                    frontend_by_time[ts_key] = []
                    
                frontend_by_time[ts_key].append(req)
            except ValueError:
                pass
        
        for req in self.requests['backend']:
            try:
                # Parse timestamp and round to the nearest second
                ts = datetime.strptime(req.get('timestamp', ''), '%d/%b/%Y:%H:%M:%S %z')
                ts_key = ts.strftime('%Y-%m-%d %H:%M:%S')
                
                if ts_key not in backend_by_time:
                    backend_by_time[ts_key] = []
                    
                backend_by_time[ts_key].append(req)
            except ValueError:
                pass
        
        # Now look for time periods where there are more backend requests than frontend
        for ts_key in sorted(backend_by_time.keys()):
            # Check if this timestamp exists in frontend
            frontend_count = len(frontend_by_time.get(ts_key, []))
            backend_count = len(backend_by_time.get(ts_key, []))
            
            # If there are more backend requests than frontend in the same time window
            if backend_count > frontend_count:
                self.findings.append({
                    'type': 'Request Count Anomaly',
                    'evidence': f'More backend requests ({backend_count}) than frontend requests ({frontend_count})',
                    'timestamp': ts_key,
                    'frontend_requests': frontend_by_time.get(ts_key, []),
                    'backend_requests': backend_by_time.get(ts_key, [])
                })
    
    def visualize_timeline(self, output_file=None):
        """Create a timeline visualization of requests and findings"""
        # Convert findings and requests to a pandas DataFrame for easier visualization
        findings_data = []
        for finding in self.findings:
            findings_data.append({
                'timestamp': finding.get('timestamp', ''),
                'type': finding.get('type', ''),
                'server': finding.get('server', ''),
                'evidence': finding.get('evidence', ''),
                'is_finding': True
            })
        
        request_data = []
        for server_type, requests in self.requests.items():
            for req in requests:
                request_data.append({
                    'timestamp': req.get('timestamp', ''),
                    'type': f"{req.get('method', '')} {req.get('path', '')}",
                    'server': server_type,
                    'status': req.get('status', ''),
                    'is_finding': False
                })
        
        # Combine data
        all_data = pd.DataFrame(findings_data + request_data)
        
        # Convert timestamp to datetime
        all_data['datetime'] = pd.to_datetime(all_data['timestamp'], format='%d/%b/%Y:%H:%M:%S %z', errors='coerce')
        
        # Sort by datetime
        all_data = all_data.sort_values('datetime')
        
        # Create the plot
        fig, ax = plt.subplots(figsize=(15, 8))
        
        # Plot requests by server
        frontend_requests = all_data[(all_data['server'] == 'frontend') & (~all_data['is_finding'])]
        backend_requests = all_data[(all_data['server'] == 'backend') & (~all_data['is_finding'])]
        
        ax.scatter(frontend_requests['datetime'], [1] * len(frontend_requests), color='blue', alpha=0.6, s=50, label='Frontend Requests')
        ax.scatter(backend_requests['datetime'], [0.5] * len(backend_requests), color='green', alpha=0.6, s=50, label='Backend Requests')
        
        # Plot findings
        findings = all_data[all_data['is_finding']]
        ax.scatter(findings['datetime'], [0] * len(findings), color='red', alpha=0.8, s=80, marker='*', label='Findings')
        
        # Annotate findings
        for _, row in findings.iterrows():
            ax.annotate(row['type'], 
                       (row['datetime'], 0),
                       xytext=(0, -20),
                       textcoords='offset points',
                       ha='center',
                       fontsize=8,
                       color='red')
        
        # Set labels and title
        ax.set_yticks([0, 0.5, 1])
        ax.set_yticklabels(['Findings', 'Backend', 'Frontend'])
        ax.set_xlabel('Time')
        ax.set_title('HTTP Request Smuggling Analysis Timeline')
        
        # Add grid and legend
        ax.grid(True, alpha=0.3)
        ax.legend()
        
        # Format the date
        date_format = DateFormatter('%H:%M:%S')
        ax.xaxis.set_major_formatter(date_format)
        fig.autofmt_xdate()
        
        # Save or show the plot
        if output_file:
            plt.savefig(output_file)
            console.print(f"[green]Timeline visualization saved to {output_file}[/green]")
        else:
            plt.tight_layout()
            plt.show()
    
    def run_analysis(self):
        """Run all analysis methods on the logs"""
        # Process frontend logs
        for log_path in self.frontend_logs:
            self.requests['frontend'].extend(self.analyze_nginx_log(log_path))
        
        # Process backend logs
        for log_path in self.backend_logs:
            self.requests['backend'].extend(self.analyze_nodejs_log(log_path))
        
        # Run the different analysis methods
        console.print("[cyan]Running timing anomaly analysis...[/cyan]")
        self.analyze_timing_anomalies()
        
        console.print("[cyan]Running header anomaly analysis...[/cyan]")
        self.analyze_header_anomalies()
        
        console.print("[cyan]Running access pattern analysis...[/cyan]")
        self.analyze_access_denied_patterns()
        
        console.print("[cyan]Correlating frontend and backend requests...[/cyan]")
        self.correlate_frontend_backend_requests()
        
        # Display the findings
        self.display_findings()
    
    def display_findings(self):
        """Display the findings in a formatted table"""
        if not self.findings:
            console.print("[yellow]No findings detected in the logs.[/yellow]")
            return
        
        # Group findings by type
        findings_by_type = {}
        for finding in self.findings:
            finding_type = finding.get('type', 'Unknown')
            if finding_type not in findings_by_type:
                findings_by_type[finding_type] = []
            
            findings_by_type[finding_type].append(finding)
        
        # Display a summary
        console.print(f"[bold green]Analysis complete. Found {len(self.findings)} potential issues:[/bold green]")
        
        summary_table = Table(title="Summary of Findings")
        summary_table.add_column("Finding Type", style="cyan")
        summary_table.add_column("Count", style="magenta")
        
        for finding_type, findings in findings_by_type.items():
            summary_table.add_row(finding_type, str(len(findings)))
        
        console.print(summary_table)
        
        # Display detailed findings
        console.print("\n[bold]Detailed Findings:[/bold]")
        
        for finding_type, findings in findings_by_type.items():
            console.print(f"\n[bold cyan]{finding_type} ({len(findings)} findings)[/bold cyan]")
            
            for i, finding in enumerate(findings[:5]):  # Show only the first 5 findings of each type
                panel_content = []
                
                # Add common fields
                if 'timestamp' in finding:
                    panel_content.append(f"Timestamp: {finding['timestamp']}")
                if 'server' in finding:
                    panel_content.append(f"Server: {finding['server']}")
                if 'ip' in finding:
                    panel_content.append(f"IP: {finding['ip']}")
                if 'request' in finding:
                    panel_content.append(f"Request: {finding['request']}")
                
                # Add type-specific fields
                if finding_type == 'Potential Request Smuggling':
                    if 'content_length' in finding:
                        panel_content.append(f"Content-Length: {finding['content_length']}")
                    if 'transfer_encoding' in finding:
                        panel_content.append(f"Transfer-Encoding: {finding['transfer_encoding']}")
                
                elif finding_type == 'Timing Anomaly':
                    if 'request_time' in finding:
                        panel_content.append(f"Request Time: {finding['request_time']} seconds")
                    if 'avg_request_time' in finding:
                        panel_content.append(f"Average Time: {finding['avg_request_time']:.2f} seconds")
                    if 'std_dev' in finding:
                        panel_content.append(f"Standard Deviation: {finding['std_dev']:.2f}")
                
                elif finding_type == 'Request Count Anomaly':
                    if 'evidence' in finding:
                        panel_content.append(f"Evidence: {finding['evidence']}")
                
                # Add raw log if available
                if 'raw_log' in finding:
                    raw_log = finding['raw_log']
                    if len(raw_log) > 100:
                        raw_log = raw_log[:100] + "..."
                    panel_content.append(f"\nRaw Log: {raw_log}")
                
                # Create and display the panel
                panel = Panel("\n".join(panel_content), title=f"Finding {i+1}", border_style="yellow")
                console.print(panel)
            
            # Indicate if there are more findings not shown
            if len(findings) > 5:
                console.print(f"[yellow]... and {len(findings) - 5} more {finding_type} findings.[/yellow]")
    
    def save_findings(self, output_file):
        """Save the findings to a JSON file"""
        with open(output_file, 'w') as f:
            json.dump(self.findings, f, indent=4)
        
        console.print(f"[green]Findings saved to {output_file}[/green]")

def main():
    parser = argparse.ArgumentParser(description="HTTP Request Smuggling Log Analyzer")
    parser.add_argument("--frontend-logs", "-f", nargs="+", help="Frontend (NGINX) log files to analyze")
    parser.add_argument("--backend-logs", "-b", nargs="+", help="Backend (Node.js) log files to analyze")
    parser.add_argument("--frontend-log-dir", help="Directory containing frontend (NGINX) log files")
    parser.add_argument("--backend-log-dir", help="Directory containing backend (Node.js) log files")
    parser.add_argument("--output", "-o", help="Output JSON file for findings")
    parser.add_argument("--visualize", "-v", help="Generate timeline visualization and save to the specified file")
    
    args = parser.parse_args()
    
    # Initialize the analyzer
    analyzer = LogAnalyzer()
    
    # Add frontend logs
    if args.frontend_logs:
        for log_file in args.frontend_logs:
            analyzer.add_frontend_log(log_file)
    
    if args.frontend_log_dir:
        for log_file in glob.glob(os.path.join(args.frontend_log_dir, "*.log")):
            analyzer.add_frontend_log(log_file)
    
    # Add backend logs
    if args.backend_logs:
        for log_file in args.backend_logs:
            analyzer.add_backend_log(log_file)
    
    if args.backend_log_dir:
        for log_file in glob.glob(os.path.join(args.backend_log_dir, "*.log")):
            analyzer.add_backend_log(log_file)
    
    # Make sure we have logs to analyze
    if not analyzer.frontend_logs and not analyzer.backend_logs:
        console.print("[bold red]Error: No log files specified for analysis![/bold red]")
        sys.exit(1)
    
    # Run the analysis
    analyzer.run_analysis()
    
    # Save findings if requested
    if args.output:
        analyzer.save_findings(args.output)
    
    # Generate visualization if requested
    if args.visualize:
        analyzer.visualize_timeline(args.visualize)

if __name__ == "__main__":
    main()