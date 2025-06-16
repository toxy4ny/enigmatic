#!/usr/bin/env python3
"""
ENIGMATIC - a WAF IP Encoder with IPv6, Burp Suite integration, domain support
Author: KL3FT3Z (https://github.com/toxy4ny)
"""

import sys
import re
import subprocess
import argparse
import random
import json
import time
import requests
import socket
import base64
import urllib.parse
from typing import List, Dict, Tuple, Optional, Union
from ipaddress import ip_address, AddressValueError, IPv6Address, IPv4Address
import dns.resolver
import yaml

class AdvancedIPEncoder:
    """Enhanced IP encoder with IPv6 and domain support"""
    
    def __init__(self):
        self.ipv4_methods = {
            'decimal_class_b': self._encode_decimal_class_b,
            'decimal_class_a': self._encode_decimal_class_a,
            'mixed_encoding': self._encode_mixed,
            'double_hex_octal': self._encode_double_hex_octal,
            'hex_octal_decimal': self._encode_hex_octal_decimal,
            'single_decimal': self._encode_single_decimal,
            'full_hex': self._encode_full_hex,
            'full_octal': self._encode_full_octal,
            'hex_segments': self._encode_hex_segments,
            'partial_hex_class_b': self._encode_partial_hex_class_b,
            'unicode_circles': self._encode_unicode_circles,
            'unicode_fullwidth': self._encode_unicode_fullwidth,
            'unicode_math': self._encode_unicode_math
        }
        
        self.ipv6_methods = {
            'compressed': self._encode_ipv6_compressed,
            'expanded': self._encode_ipv6_expanded,
            'mixed_notation': self._encode_ipv6_mixed,
            'zero_compressed': self._encode_ipv6_zero_compressed,
            'leading_zeros': self._encode_ipv6_leading_zeros,
            'bracket_notation': self._encode_ipv6_bracket_notation
        }
        
        self.domain_methods = {
            'url_encode': self._encode_domain_url,
            'unicode_encode': self._encode_domain_unicode,
            'punycode': self._encode_domain_punycode,
            'case_variation': self._encode_domain_case,
            'subdomain_bypass': self._encode_subdomain_bypass
        }
    
    def validate_target(self, target: str) -> Tuple[str, str]:
        """Validate and classify target (IPv4, IPv6, domain)"""
        try:
            addr = ip_address(target)
            if isinstance(addr, IPv4Address):
                return 'ipv4', target
            else:
                return 'ipv6', target
        except AddressValueError:
           
            if self._is_domain(target):
                return 'domain', target
            else:
                raise ValueError(f"Invalid target: {target}")
    
    def _is_domain(self, target: str) -> bool:
        """Check if target is a valid domain name"""
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        return bool(domain_pattern.match(target))
    
    def _encode_decimal_class_b(self, ip_str: str) -> str:
        octets = list(map(int, ip_str.split('.')))
        return f"{octets[0]}.{octets[1]}.{octets[2] * 256 + octets[3]}"
    
    def _encode_decimal_class_a(self, ip_str: str) -> str:
        octets = list(map(int, ip_str.split('.')))
        return f"{octets[0]}.{octets[1] * 65536 + octets[2] * 256 + octets[3]}"
    
    def _encode_mixed(self, ip_str: str) -> str:
        octets = list(map(int, ip_str.split('.')))
        return f"0x{octets[0]:02x}.{octets[1]}.{octets[2]:03o}.{octets[3]:03o}"
    
    def _encode_double_hex_octal(self, ip_str: str) -> str:
        octets = list(map(int, ip_str.split('.')))
        return f"0x{octets[0]:02x}.0x{octets[1]:02x}.{octets[2]:03o}.{octets[3]:03o}"
    
    def _encode_hex_octal_decimal(self, ip_str: str) -> str:
        octets = list(map(int, ip_str.split('.')))
        return f"0x{octets[0]:02x}.{octets[1]:03o}.{octets[2]}.{octets[3]}"
    
    def _encode_single_decimal(self, ip_str: str) -> str:
        octets = list(map(int, ip_str.split('.')))
        return str((octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3])
    
    def _encode_full_hex(self, ip_str: str) -> str:
        octets = list(map(int, ip_str.split('.')))
        return f"0x{(octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]:08x}"
    
    def _encode_full_octal(self, ip_str: str) -> str:
        octets = list(map(int, ip_str.split('.')))
        return '.'.join([f"{octet:03o}" for octet in octets])
    
    def _encode_hex_segments(self, ip_str: str) -> str:
        octets = list(map(int, ip_str.split('.')))
        return '.'.join([f"0x{octet:x}" for octet in octets])
    
    def _encode_partial_hex_class_b(self, ip_str: str) -> str:
        octets = list(map(int, ip_str.split('.')))
        return f"{octets[0]}.{octets[1]}.0x{octets[2] * 256 + octets[3]:x}"
    
    def _encode_unicode_circles(self, ip_str: str) -> str:
        unicode_map = {'0': '⓪', '1': '①', '2': '②', '3': '③', '4': '④', 
                      '5': '⑤', '6': '⑥', '7': '⑦', '8': '⑧', '9': '⑨'}
        return ''.join([unicode_map.get(c, c) for c in ip_str])
    
    def _encode_unicode_fullwidth(self, ip_str: str) -> str:
        unicode_map = {'0': '０', '1': '１', '2': '２', '3': '３', '4': '４',
                      '5': '５', '6': '６', '7': '７', '8': '８', '9': '９', '.': '.'}
        return ''.join([unicode_map.get(c, c) for c in ip_str])
    
    def _encode_unicode_math(self, ip_str: str) -> str:
        unicode_map = {'0': '𝟘', '1': '𝟙', '2': '𝟚', '3': '𝟛', '4': '𝟜',
                      '5': '𝟝', '6': '𝟞', '7': '𝟟', '8': '𝟠', '9': '𝟡', '.': '.'}
        return ''.join([unicode_map.get(c, c) for c in ip_str])
    
    def _encode_ipv6_compressed(self, ipv6_str: str) -> str:
        """Compress IPv6 address using :: notation"""
        try:
            addr = IPv6Address(ipv6_str)
            return addr.compressed
        except:
            return ipv6_str
    
    def _encode_ipv6_expanded(self, ipv6_str: str) -> str:
        """Expand IPv6 address to full form"""
        try:
            addr = IPv6Address(ipv6_str)
            return addr.exploded
        except:
            return ipv6_str
    
    def _encode_ipv6_mixed(self, ipv6_str: str) -> str:
        """IPv6 with embedded IPv4 notation"""
        try:
            addr = IPv6Address(ipv6_str)
            if addr.ipv4_mapped:
                return f"::ffff:{addr.ipv4_mapped}"
            return str(addr)
        except:
            return ipv6_str
    
    def _encode_ipv6_zero_compressed(self, ipv6_str: str) -> str:
        """Alternative zero compression"""
        try:
            addr = IPv6Address(ipv6_str)
            compressed = str(addr)
    
            return compressed.replace(':0000:', '::').replace(':000:', '::')
        except:
            return ipv6_str
    
    def _encode_ipv6_leading_zeros(self, ipv6_str: str) -> str:
        """Add leading zeros to all segments"""
        try:
            addr = IPv6Address(ipv6_str)
            parts = addr.exploded.split(':')
            return ':'.join([f"{part.zfill(4)}" for part in parts])
        except:
            return ipv6_str
    
    def _encode_ipv6_bracket_notation(self, ipv6_str: str) -> str:
        """Bracket notation for URLs"""
        return f"[{ipv6_str}]"
    
    
    def _encode_domain_url(self, domain: str) -> str:
        """URL encode domain"""
        return urllib.parse.quote(domain, safe='')
    
    def _encode_domain_unicode(self, domain: str) -> str:
        """Unicode domain encoding"""
        try:
            return domain.encode('unicode_escape').decode('ascii')
        except:
            return domain
    
    def _encode_domain_punycode(self, domain: str) -> str:
        """Punycode encoding for internationalized domains"""
        try:
            return domain.encode('idna').decode('ascii')
        except:
            return domain
    
    def _encode_domain_case(self, domain: str) -> str:
        """Random case variation"""
        return ''.join([c.upper() if random.choice([True, False]) else c.lower() 
                       for c in domain])
    
    def _encode_subdomain_bypass(self, domain: str) -> str:
        """Add bypass subdomain"""
        bypasses = ['www', 'mail', 'ftp', 'admin', 'test', 'dev']
        return f"{random.choice(bypasses)}.{domain}"
    
    def encode_target(self, target: str, method: str) -> str:
        """Encode target using specified method"""
        target_type, validated_target = self.validate_target(target)
        
        if target_type == 'ipv4':
            if method in self.ipv4_methods:
                return self.ipv4_methods[method](validated_target)
        elif target_type == 'ipv6':
            if method in self.ipv6_methods:
                return self.ipv6_methods[method](validated_target)
        elif target_type == 'domain':
            if method in self.domain_methods:
                return self.domain_methods[method](validated_target)
        
        raise ValueError(f"Method {method} not supported for {target_type}")
    
    def get_available_methods(self, target: str) -> List[str]:
        """Get available encoding methods for target"""
        target_type, _ = self.validate_target(target)
        
        if target_type == 'ipv4':
            return list(self.ipv4_methods.keys())
        elif target_type == 'ipv6':
            return list(self.ipv6_methods.keys())
        elif target_type == 'domain':
            return list(self.domain_methods.keys())
        
        return []

class BurpSuiteIntegration:
    """Burp Suite API integration"""
    
    def __init__(self, burp_host='127.0.0.1', burp_port=8080, api_key=None):
        self.burp_host = burp_host
        self.burp_port = burp_port
        self.api_key = api_key
        self.session = requests.Session()
        
        if api_key:
            self.session.headers.update({'X-API-Key': api_key})
    
    def send_request(self, url: str, method: str = 'GET', data: str = None) -> Dict:
        """Send request through Burp proxy"""
        proxies = {
            'http': f'http://{self.burp_host}:{self.burp_port}',
            'https': f'http://{self.burp_host}:{self.burp_port}'
        }
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                data=data,
                proxies=proxies,
                timeout=30,
                verify=False
            )
            
            return {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content_length': len(response.content),
                'response_time': response.elapsed.total_seconds()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_scan_results(self, scan_id: str) -> Dict:
        """Get scan results from Burp"""
        try:
            response = self.session.get(f'http://{self.burp_host}:{self.burp_port}/burp/scanner/scans/{scan_id}')
            return response.json()
        except Exception as e:
            return {'error': str(e)}

class HTTPStatusAnalyzer:
    """HTTP response analysis for bypass detection"""
    
    def __init__(self):
        self.success_indicators = [200, 201, 202, 204, 301, 302, 307, 308]
        self.waf_indicators = [403, 406, 418, 429, 503]
        self.bypass_keywords = [
            'Welcome', 'Login', 'Dashboard', 'Admin', 'Success',
            'Index', 'Home', 'Content', 'Data'
        ]
        self.waf_keywords = [
            'Blocked', 'Forbidden', 'Access denied', 'WAF', 'Firewall',
            'CloudFlare', 'Akamai', 'Incapsula', 'ModSecurity'
        ]
    
    def analyze_response(self, status_code: int, content: str, headers: Dict) -> Dict:
        """Analyze HTTP response for WAF bypass indicators"""
        analysis = {
            'likely_bypass': False,
            'likely_blocked': False,
            'confidence': 0.0,
            'indicators': []
        }
        
        if status_code in self.success_indicators:
            analysis['likely_bypass'] = True
            analysis['confidence'] += 0.4
            analysis['indicators'].append(f'Success status: {status_code}')
        elif status_code in self.waf_indicators:
            analysis['likely_blocked'] = True
            analysis['confidence'] += 0.6
            analysis['indicators'].append(f'WAF status: {status_code}')
        
        content_lower = content.lower()
        bypass_matches = sum(1 for keyword in self.bypass_keywords 
                           if keyword.lower() in content_lower)
        waf_matches = sum(1 for keyword in self.waf_keywords 
                         if keyword.lower() in content_lower)
        
        if bypass_matches > 0:
            analysis['likely_bypass'] = True
            analysis['confidence'] += 0.3 * (bypass_matches / len(self.bypass_keywords))
            analysis['indicators'].append(f'Bypass keywords: {bypass_matches}')
        
        if waf_matches > 0:
            analysis['likely_blocked'] = True
            analysis['confidence'] += 0.4 * (waf_matches / len(self.waf_keywords))
            analysis['indicators'].append(f'WAF keywords: {waf_matches}')
        
        waf_headers = ['cf-ray', 'x-sucuri-id', 'x-iinfo', 'x-wzws-requested-method']
        for header in waf_headers:
            if header.lower() in [h.lower() for h in headers.keys()]:
                analysis['likely_blocked'] = True
                analysis['confidence'] += 0.2
                analysis['indicators'].append(f'WAF header: {header}')
        
        return analysis

class DomainResolver:
    """Domain resolution and DNS manipulation"""
    
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
    
    def resolve_domain(self, domain: str) -> Dict:
        """Resolve domain to IP addresses"""
        results = {'ipv4': [], 'ipv6': [], 'cname': [], 'mx': []}
        
        try:

            a_records = self.resolver.resolve(domain, 'A')
            results['ipv4'] = [str(record) for record in a_records]
        except:
            pass
        
        try:

            aaaa_records = self.resolver.resolve(domain, 'AAAA')
            results['ipv6'] = [str(record) for record in aaaa_records]
        except:
            pass
        
        try:

            cname_records = self.resolver.resolve(domain, 'CNAME')
            results['cname'] = [str(record) for record in cname_records]
        except:
            pass
        
        try:
           
            mx_records = self.resolver.resolve(domain, 'MX')
            results['mx'] = [str(record) for record in mx_records]
        except:
            pass
        
        return results
    
    def get_alternative_domains(self, domain: str) -> List[str]:
        """Get alternative domains (subdomains, similar domains)"""
        alternatives = []
        
        subdomains = ['www', 'mail', 'ftp', 'blog', 'shop', 'api', 'admin', 'test']
        for sub in subdomains:
            alternatives.append(f"{sub}.{domain}")
        
        tlds = ['.com', '.net', '.org', '.io', '.co']
        base_domain = domain.rsplit('.', 1)[0]
        for tld in tlds:
            if not domain.endswith(tld):
                alternatives.append(f"{base_domain}{tld}")
        
        return alternatives

class AdvancedWAFBypassTool:
    """Enhanced WAF bypass tool with all new features"""
    
    def __init__(self, config_file: str = None):
        self.encoder = AdvancedIPEncoder()
        self.burp = None
        self.http_analyzer = HTTPStatusAnalyzer()
        self.dns_resolver = DomainResolver()
        self.success_log = []
        self.verbose = False
        self.config = self.load_config(config_file)
    
    def load_config(self, config_file: str) -> Dict:
        """Load configuration from YAML file"""
        default_config = {
            'default_delay': 1.0,
            'http_timeout': 30,
            'max_redirects': 5,
            'user_agents': [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
            ]
        }
        
        if config_file:
            try:
                with open(config_file, 'r') as f:
                    user_config = yaml.safe_load(f)
                    default_config.update(user_config)
            except Exception as e:
                print(f"[!] Warning: Could not load config file: {e}")
        
        return default_config
    
    def setup_burp_integration(self, host: str = '127.0.0.1', port: int = 8080, api_key: str = None):
        """Setup Burp Suite integration"""
        self.burp = BurpSuiteIntegration(host, port, api_key)
        if self.verbose:
            print(f"[+] Burp Suite integration enabled: {host}:{port}")
    
    def find_targets_in_command(self, command: List[str]) -> Dict[str, List[Tuple[int, str]]]:
        """Find all targets (IPs and domains) in command"""
        targets = {'ipv4': [], 'ipv6': [], 'domain': []}
        
        ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ipv6_pattern = r'\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b'
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        
        for i, arg in enumerate(command):
           
            ipv4_matches = re.findall(ipv4_pattern, arg)
            for match in ipv4_matches:
                try:
                    ip_address(match)  
                    targets['ipv4'].append((i, match))
                except:
                    pass
            
            
            ipv6_matches = re.findall(ipv6_pattern, arg)
            for match in ipv6_matches:
                try:
                    ip_address(match)  
                    targets['ipv6'].append((i, match))
                except:
                    pass
            
            
            domain_matches = re.findall(domain_pattern, arg)
            for match in domain_matches:
                if self.encoder._is_domain(match):
                    targets['domain'].append((i, match))
        
        return targets
    
    def test_http_bypass(self, url: str, encoded_target: str, original_target: str) -> Dict:
        """Test HTTP bypass with encoded target"""
        test_url = url.replace(original_target, encoded_target)
        
        try:
            
            response = requests.get(
                test_url,
                timeout=self.config['http_timeout'],
                allow_redirects=True,
                headers={'User-Agent': random.choice(self.config['user_agents'])},
                verify=False
            )
            
            analysis = self.http_analyzer.analyze_response(
                response.status_code,
                response.text,
                response.headers
            )
            
            result = {
                'url': test_url,
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds(),
                'content_length': len(response.content),
                'analysis': analysis,
                'success': analysis['likely_bypass']
            }
            
           
            if self.burp:
                burp_result = self.burp.send_request(test_url)
                result['burp_data'] = burp_result
            
            return result
            
        except Exception as e:
            return {'error': str(e), 'url': test_url}
    
    def run_comprehensive_test(self, command: List[str], profile: str = 'default') -> Dict:
        """Run comprehensive bypass testing"""
        
        targets = self.find_targets_in_command(command)
        total_targets = sum(len(target_list) for target_list in targets.values())
        
        if total_targets == 0:
            return {'error': 'No targets found in command'}
        
        if self.verbose:
            print(f"[+] Found targets: IPv4={len(targets['ipv4'])}, IPv6={len(targets['ipv6'])}, Domains={len(targets['domain'])}")
        
        results = {
            'targets': targets,
            'successful_bypasses': [],
            'failed_attempts': [],
            'dns_resolutions': {},
            'burp_scans': []
        }
        
        
        for target_type, target_list in targets.items():
            for pos, target in target_list:
                if self.verbose:
                    print(f"[+] Testing {target_type}: {target}")
                
                
                if target_type == 'domain':
                    dns_info = self.dns_resolver.resolve_domain(target)
                    results['dns_resolutions'][target] = dns_info
                    
                    
                    alt_domains = self.dns_resolver.get_alternative_domains(target)
                    for alt_domain in alt_domains[:3]:  
                        try:
                            available_methods = self.encoder.get_available_methods(alt_domain)
                            for method in available_methods[:2]: 
                                encoded = self.encoder.encode_target(alt_domain, method)
                                
                        except Exception as e:
                            if self.verbose:
                                print(f"[!] Alt domain test failed: {e}")
                
               
                available_methods = self.encoder.get_available_methods(target)
                
               
                for method in available_methods:
                    try:
                        encoded_target = self.encoder.encode_target(target, method)
                        
                       
                        http_urls = [arg for arg in command if arg.startswith(('http://', 'https://'))]
                        for url in http_urls:
                            if target in url:
                                http_result = self.test_http_bypass(url, encoded_target, target)
                                if http_result.get('success'):
                                    results['successful_bypasses'].append({
                                        'target': target,
                                        'method': method,
                                        'encoded': encoded_target,
                                        'type': 'http',
                                        'result': http_result
                                    })
                                else:
                                    results['failed_attempts'].append({
                                        'target': target,
                                        'method': method,
                                        'encoded': encoded_target,
                                        'type': 'http',
                                        'result': http_result
                                    })
                        
                       
                        modified_command = command.copy()
                        modified_command[pos] = modified_command[pos].replace(target, encoded_target)
                        
                        success, stdout, stderr = self.execute_command(modified_command)
                        
                        test_result = {
                            'target': target,
                            'method': method,
                            'encoded': encoded_target,
                            'type': 'command',
                            'success': success,
                            'stdout_length': len(stdout),
                            'stderr_length': len(stderr),
                            'command': ' '.join(modified_command)
                        }
                        
                        if success:
                            results['successful_bypasses'].append(test_result)
                        else:
                            results['failed_attempts'].append(test_result)
                        
                        
                        time.sleep(self.config['default_delay'])
                        
                    except Exception as e:
                        if self.verbose:
                            print(f"[!] Error testing {method} on {target}: {e}")
        
        return results
    
    def execute_command(self, command: List[str], timeout: int = None) -> Tuple[bool, str, str]:
        """Execute command with timeout"""
        if timeout is None:
            timeout = self.config['http_timeout']
        
        try:
            if self.verbose:
                print(f"[+] Executing: {' '.join(command)}")
            
            result = subprocess.run(
                command, 
                capture_output=True, 
                text=True, 
                timeout=timeout
            )
            
            return result.returncode == 0, result.stdout, result.stderr
            
        except subprocess.TimeoutExpired:
            return False, "", "Command timeout"
        except Exception as e:
            return False, "", str(e)

def main():
    parser = argparse.ArgumentParser(
        description='ENIGMATIC - a WAF IP Encoder with IPv6, Burp Suite API, and Domain support by FL3FT3Z (https://github.com/toxy4ny)',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('command', nargs='*', help='Command to execute')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-c', '--config', help='Configuration file')
    parser.add_argument('--burp-host', default='127.0.0.1', help='Burp Suite host')
    parser.add_argument('--burp-port', type=int, default=8080, help='Burp Suite port')
    parser.add_argument('--burp-key', help='Burp Suite API key')
    parser.add_argument('--test-target', help='Test all encodings for specific target')
    parser.add_argument('--profile', default='default', help='Testing profile')
    parser.add_argument('-o', '--output', help='Output file for results')
    
    args = parser.parse_args()
    
    tool = AdvancedWAFBypassTool(args.config)
    tool.verbose = args.verbose
    
    if args.burp_key:
        tool.setup_burp_integration(args.burp_host, args.burp_port, args.burp_key)
    
    if args.test_target:
        try:
            target_type, validated_target = tool.encoder.validate_target(args.test_target)
            methods = tool.encoder.get_available_methods(validated_target)
            
            print(f"Target: {args.test_target} (Type: {target_type})")
            print(f"Available methods: {len(methods)}")
            
            for method in methods:
                try:
                    encoded = tool.encoder.encode_target(validated_target, method)
                    print(f"{method:20s}: {encoded}")
                except Exception as e:
                    print(f"{method:20s}: Error - {e}")
        except Exception as e:
            print(f"[!] Error: {e}")
        return
    
   
    if args.command:
        results = tool.run_comprehensive_test(args.command, args.profile)
        
        print(f"\n=== Advanced WAF Bypass Results ===")
        print(f"Successful bypasses: {len(results['successful_bypasses'])}")
        print(f"Failed attempts: {len(results['failed_attempts'])}")
        
        if results['successful_bypasses']:
            print(f"\n=== Successful Bypasses ===")
            for bypass in results['successful_bypasses']:
                print(f"✓ {bypass['target']} -> {bypass['encoded']} ({bypass['method']})")
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"[+] Results saved to {args.output}")
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
