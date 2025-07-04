import argparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from typing import List, Dict
from scanner.network import AdvancedNetworkScanner
from scanner.wifi import WiFiScanner
from scanner.vulnerability import VulnerabilityScanner

console = Console()

def display_results(devices: List[Dict]) -> None:
    """Display comprehensive scan results with hostnames"""
    table = Table(title="Network Scan Results", expand=True)
    table.add_column("IP", style="cyan")
    table.add_column("Hostname", style="magenta")
    table.add_column("MAC")
    table.add_column("Vendor")
    table.add_column("OS")
    table.add_column("Open Ports")
    
    for device in devices:
        ports = "\n".join(
            f"{port}: {svc['name']}" if isinstance(svc, dict) else f"{port}: {svc}"
            for port, svc in device.get('ports', {}).items()
        )
        table.add_row(
            device['ip'],
            device.get('hostname', 'N/A'),
            device['mac'],
            device.get('vendor', 'Unknown'),
            device.get('os', 'Unknown'),
            ports or "None"
        )
    
    console.print(Panel.fit(table))

def display_vulnerabilities(vulns: List[Dict], ip: str) -> None:
    """Display vulnerabilities in a rich table"""
    if not vulns:
        console.print(f"[green]No vulnerabilities found for {ip}![/green]")
        return
        
    table = Table(title=f"Vulnerabilities for {ip}", expand=True)
    table.add_column("Service", style="cyan")
    table.add_column("Port")
    table.add_column("CVE ID", style="red")
    table.add_column("Severity", style="bold")
    table.add_column("Score")
    table.add_column("Description")
    
    for vuln in vulns:
        severity_color = {
            "CRITICAL": "red",
            "HIGH": "bright_red",
            "MEDIUM": "yellow",
            "LOW": "green",
            "UNKNOWN": "white"
        }.get(vuln['severity'], "white")
        
        table.add_row(
            vuln['service'],
            str(vuln['port']),
            vuln['cve_id'],
            f"[{severity_color}]{vuln['severity']}[/{severity_color}]",
            str(vuln['score']),
            vuln['description'][:100] + "..." if len(vuln['description']) > 100 else vuln['description']
        )
    
    console.print(Panel.fit(table))
    console.print("\n[bold]References:[/bold]")
    for vuln in vulns:
        if vuln.get('references'):
            console.print(f"[underline]{vuln['cve_id']}[/underline]:")
            for ref in vuln['references'][:3]:  # Show first 3 references
                console.print(f"  • {ref}")

def main():
    parser = argparse.ArgumentParser(description="Advanced Network Scanner")
    subparsers = parser.add_subparsers(dest='command', required=True)
    
    # Network scan command
    net_parser = subparsers.add_parser('scan', help='Scan the network')
    net_parser.add_argument('ip_range', help='IP range to scan (e.g., 192.168.1.0/24)')
    net_parser.add_argument('-p', '--ports', nargs='+', type=int, 
                          help='Ports to scan (default: common ports)')
    net_parser.add_argument('-v', '--vulnerabilities', action='store_true',
                        help='Check for vulnerabilities')
    net_parser.add_argument('--verbose', action='store_true',
                        help='Show detailed vulnerability scan information')
    net_parser.add_argument('--api-key', help='NVD API key for vulnerability scanning')
    
    # WiFi scan command
    wifi_parser = subparsers.add_parser('wifi', help='Scan WiFi networks')
    wifi_parser.add_argument('-i', '--interface', default=None,
                        help='Network interface to use (default: auto-detect)')
    wifi_parser.add_argument('-t', '--timeout', type=int, default=10,
                        help='Scan duration in seconds')
    wifi_parser.add_argument('-l', '--list', action='store_true',
                        help='List available interfaces')
    
    args = parser.parse_args()
    
    if args.command == 'scan':
        scanner = AdvancedNetworkScanner()
        devices = scanner.scan(args.ip_range, args.ports)
        display_results(devices)
        
        if args.vulnerabilities:
            vuln_scanner = VulnerabilityScanner(api_key=args.api_key)
            for device in devices:
                if device.get('ports'):
                    console.print(f"\n[bold]Scanning vulnerabilities for {device['ip']}:[/bold]")
                    
                    # Enable debug logging if verbose flag is set
                    if args.verbose:
                        logger.setLevel(logging.DEBUG)
                    
                    vulns = vuln_scanner.scan_device(device)
                    
                    if not vulns:
                        console.print(f"[yellow]No known vulnerabilities detected for {device['ip']}[/yellow]")
                        console.print("[dim]Note: This might mean either:\n"
                                    "1. The services are secure\n"
                                    "2. The services aren't in the NVD database\n"
                                    "3. The version information wasn't specific enough[/dim]")
                    else:
                        display_vulnerabilities(vulns, device['ip'])
                    
    elif args.command == 'wifi':
        if args.list:
            try:
                ifaces = WiFiScanner.list_interfaces()
                table = Table(title="Available Interfaces")
                table.add_column("Name")
                table.add_column("Description")
                table.add_column("Type")
                table.add_column("MAC")
                for iface in ifaces:
                    table.add_row(
                        iface['name'],
                        iface.get('description', ''),
                        str(iface.get('type', '')),
                        iface.get('mac', '')
                    )
                console.print(Panel.fit(table))
            except Exception as e:
                console.print(f"[red]Error listing interfaces: {e}[/red]")
        else:
            try:
                wifi = WiFiScanner(args.interface)
                networks = wifi.scan_networks(args.timeout)
                if not networks.empty:
                    console.print(Panel.fit(networks.to_string()))
                else:
                    console.print("[red]No WiFi networks found![/red]")
            except Exception as e:
                console.print(f"[red]WiFi scan failed: {e}[/red]")

if __name__ == "__main__":
    main()