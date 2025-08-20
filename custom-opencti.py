#!/usr/bin/env python3

# Copyright Andreas Misje 2024, 2022 Aurora Networks Managed Services
# See https://github.com/misje/wazuh-opencti for documentation
# Modified by Brian Dao
# Modified by nauliajati@tangerangkota.go.id (TangerangKota-CSIRT)
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import sys
import os
from socket import socket, AF_UNIX, SOCK_DGRAM
from datetime import date, datetime, timedelta
import time
import requests
from requests.exceptions import ConnectionError, Timeout, RequestException
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import json
import ipaddress
import re
import traceback
import logging
from functools import lru_cache
from typing import List, Dict, Optional, Any
import threading
from contextlib import contextmanager
import signal
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# Configuration constants
MAX_IND_ALERTS = 5  # Increased for better coverage
MAX_OBS_ALERTS = 5  # Increased for better coverage
REQUEST_TIMEOUT = 45  # Increased for production stability
MAX_RETRIES = 5  # More resilient retry strategy
BACKOFF_FACTOR = 1.0  # More aggressive backoff for production
CONNECTION_POOL_SIZE = 20  # Increased pool size for concurrent requests
# Debug can be enabled by setting the internal configuration setting
# integration.debug to 1 or higher:
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
url = ''
# Match SHA256:
regex_file_hash = re.compile('[A-Fa-f0-9]{64}')
# Match sysmon_eventX, sysmon_event_XX, sysmon_eidX_detections, and sysmon_process-anomalies:
sha256_sysmon_event_regex = re.compile('sysmon_(?:(?:event_?|eid)(?:1|6|7|15|23|24|25)(?:_detections)?|process-anomalies)')
# Match sysmon_event3 and sysmon_eid3_detections:
sysmon_event3_regex = re.compile('sysmon_(?:event|eid)3(?:_detections)?')
# Match sysmon_event_22 and sysmon_eid22_detections:
sysmon_event22_regex = re.compile('sysmon_(?:event_?|eid)22(?:_detections)?')
# Location of source events file:
log_file = '/var/ossec/logs/debug-custom-opencti.log'
# UNIX socket to send detections events to:
socket_addr = '/var/ossec/queue/sockets/queue'

# Ensure log directory exists
def ensure_log_directory(log_path):
    log_dir = os.path.dirname(log_path)
    if not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir, exist_ok=True)
            return log_path
        except OSError:
            # Fallback to temp directory if cannot create log directory
            return '/tmp/debug-custom-opencti.log'
    return log_path
            
# Initialize log directory and update log_file if needed
log_file = ensure_log_directory(log_file)
# Find ";"-separated entries that are not prefixed with "type: X ". In order to
# avoid non-fixed-width look-behind, match against the unwanted prefix, but
# only group the match we care about, and filter out the empty strings later:
dns_results_regex = re.compile(r'type:\s*\d+\s*[^;]+|([^\s;]+)')

# Set up logging with error handling
try:
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s",
        filemode='a'
    )
except (IOError, OSError):
    # Fallback to console logging if file logging fails
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s"
    )
    
logger = logging.getLogger(__name__)

# Thread-safe session with connection pooling
_session_lock = threading.Lock()
_session_instance = None

# Production monitoring
_request_count = 0
_error_count = 0
_start_time = time.time()

def log_performance_metrics():
    """Log performance metrics for production monitoring"""
    global _request_count, _error_count, _start_time
    uptime = time.time() - _start_time
    error_rate = (_error_count / max(_request_count, 1)) * 100
    
    memory_info = ""
    if PSUTIL_AVAILABLE:
        try:
            memory_mb = psutil.Process().memory_info().rss / 1024 / 1024
            memory_info = f", Memory: {memory_mb:.1f}MB"
        except:
            memory_info = ", Memory: N/A"
    
    # Log performance metrics less frequently in production to reduce log volume
    if _request_count % 50 == 0 or error_rate > 5.0:  # Every 50 requests or if error rate > 5%
        logger.info(f"Performance metrics - Uptime: {uptime:.1f}s, "
                   f"Requests: {_request_count}, Errors: {_error_count}, "
                   f"Error rate: {error_rate:.1f}%{memory_info}")
    else:
        logger.debug(f"Performance - Requests: {_request_count}, Errors: {_error_count}")

def increment_request_counter():
    """Thread-safe request counter increment"""
    global _request_count
    with _session_lock:
        _request_count += 1

def increment_error_counter():
    """Thread-safe error counter increment"""
    global _error_count
    with _session_lock:
        _error_count += 1

def get_session():
    global _session_instance
    if _session_instance is None:
        with _session_lock:
            if _session_instance is None:
                _session_instance = requests.Session()
                retry_strategy = Retry(
                    total=MAX_RETRIES,
                    backoff_factor=BACKOFF_FACTOR,
                    status_forcelist=[429, 500, 502, 503, 504],
                    allowed_methods=["POST", "GET"],  # Production safety
                    raise_on_status=False  # Don't raise on HTTP errors, handle gracefully
                )
                adapter = HTTPAdapter(
                    max_retries=retry_strategy,
                    pool_connections=CONNECTION_POOL_SIZE,
                    pool_maxsize=CONNECTION_POOL_SIZE
                )
                _session_instance.mount("http://", adapter)
                _session_instance.mount("https://", adapter)
    return _session_instance

def main(args):
    global url
    logger.info('Starting OpenCTI-Wazuh connector')
    alert_path = args[1]
    token = args[2]
    url = args[3]

    try:
        with open(alert_path, 'r', encoding='utf-8', errors='ignore') as alert_file:
            alert = json.load(alert_file)
    except (IOError, json.JSONDecodeError) as e:
        logger.error(f"Failed to load alert file {alert_path}: {e}")
        sys.exit(1)

    # Validate Wazuh log structure
    if not validate_wazuh_log_structure(alert):
        logger.error("Invalid Wazuh log structure detected")
        try:
            send_error_event('Invalid Wazuh log structure', alert.get('agent'))
        except Exception as e:
            logger.error(f"Failed to send error event: {e}")
        sys.exit(1)
        
    # Normalize field names for compatibility
    alert = normalize_wazuh_fields(alert)
    
    logger.info(f'Processing alert ID: {alert.get("id", "unknown")}')
    logger.debug(f'Alert details: {json.dumps(alert, indent=2)[:500]}...')

    try:
        for new_alert in query_opencti(alert, url, token):
            send_event(new_alert, alert['agent'])
        # Reduce success logging frequency in production
        if _request_count % 10 == 0:  # Log every 10th successful processing
            logger.info(f'Alert processing completed successfully (#{_request_count})')
        else:
            logger.debug('Alert processing completed successfully')
        
        # Log performance metrics every 100 requests or on error
        if _request_count % 100 == 0 or _error_count > 0:
            log_performance_metrics()
            
    except Exception as e:
        increment_error_counter()
        logger.error(f"Alert processing failed: {e}")
        send_error_event(f'Alert processing failed: {e}', alert['agent'])
        log_performance_metrics()  # Log metrics on error
        raise

@contextmanager
def safe_file_operation(file_path: str, mode: str = 'a'):
    """Context manager for safe file operations"""
    file_handle = None
    try:
        file_handle = open(file_path, mode)
        yield file_handle
    except IOError as e:
        logger.error(f"File operation failed for {file_path}: {e}")
        raise
    finally:
        if file_handle:
            file_handle.close()

def debug(msg: str, do_log: bool = False) -> None:
    """Debug logging function"""
    do_log |= debug_enabled
    if not do_log:
        return
    
    try:
        now = time.strftime('%a %b %d %H:%M:%S %Z %Y')
        msg = f'{now}: {msg}\n'
        with safe_file_operation(log_file, 'a') as f:
            f.write(msg)
    except Exception as e:
        logger.error(f"Debug logging failed: {e}")

def log(msg: str) -> None:
    """Simple logging wrapper"""
    debug(msg, do_log=True)

# Recursively remove all empty nulls, strings, empty arrays and empty dicts
# from a dict:
def remove_empties(value: Any) -> Any:
    """Recursively remove empty values from nested structures"""
    def empty(val: Any) -> bool:
        return False if isinstance(val, bool) else not bool(val)
    
    if isinstance(value, list):
        return [x for x in (remove_empties(x) for x in value) if not empty(x)]
    elif isinstance(value, dict):
        return {k: v for k, v in ((k, remove_empties(v)) for k, v in value.items()) if not empty(v)}
    else:
        return value

# Given an object 'output' with a list of objects (edges and nodes) at key
# 'listKey', create a new list at key 'newKey' with just values from the
# original list's objects at key 'valueKey'. Example:
# {'objectLabel': {'edges': [{'node': {'value': 'cryptbot'}}, {'node': {'value': 'exe'}}]}}
# →
# {'labels:': ['cryptbot', 'exe']}
# {'objectLabel': [{'value': 'cryptbot'}, {'value': 'exe'}]}
# →
# {'labels:': ['cryptbot', 'exe']}
def simplify_objectlist(output: Dict[str, Any], listKey: str, valueKey: str, newKey: str) -> None:
    """Simplify GraphQL object lists to simple value arrays"""
    try:
        if listKey not in output:
            return
            
        if 'edges' in output[listKey]:
            edges = output[listKey]['edges']
            output[newKey] = [key[valueKey] for edge in edges for _, key in edge.items() if valueKey in key]
        else:
            output[newKey] = [key[valueKey] for key in output[listKey] if valueKey in key]

        if newKey != listKey:
            del output[listKey]
    except (KeyError, TypeError) as e:
        logger.warning(f"Failed to simplify object list {listKey}: {e}")

# Take a string, like
# "type:  5 youtube-ui.l.google.com;::ffff:142.250.74.174;::ffff:216.58.207.206;::ffff:172.217.21.174;::ffff:142.250.74.46;::ffff:142.250.74.110;::ffff:142.250.74.78;::ffff:216.58.207.238;::ffff:142.250.74.142;",
# discard records other than A/AAAA, ignore non-global addresses, and convert
# IPv4-mapped IPv6 to IPv4:
@lru_cache(maxsize=1000)
def format_dns_results(results: str) -> List[str]:
    """Process DNS results and extract valid global IP addresses"""
    def unmap_ipv6(addr: ipaddress._BaseAddress) -> ipaddress._BaseAddress:
        if isinstance(addr, ipaddress.IPv4Address):
            return addr
        v4 = getattr(addr, 'ipv4_mapped', None)
        return v4 if v4 else addr

    try:
        # Extract only A/AAAA records
        extracted = list(filter(len, dns_results_regex.findall(results)))
        
        # Convert IPv4-mapped IPv6 to IPv4 and filter global addresses
        valid_ips = []
        for result in extracted:
            try:
                addr = ipaddress.ip_address(result)
                unmapped = unmap_ipv6(addr)
                if unmapped.is_global:
                    valid_ips.append(unmapped.exploded)
            except ValueError:
                continue
                
        return valid_ips
    except Exception as e:
        logger.warning(f"DNS results parsing failed: {e}")
        return []

# Determine whether alert contains a packetbeat DNS query:
def packetbeat_dns(alert):
    return all(key in alert['data'] for key in ('method', 'dns')) and alert['data']['method'] == 'QUERY'

# For every object in dns.answers, retrieve "data", but only if "type" is
# A/AAAA and the resulting address is a global IP address:
def filter_packetbeat_dns(results):
    return [r['data'] for r in results if (r['type'] == 'A' or r['type'] == 'AAAA') and ipaddress.ip_address(r['data']).is_global]

# Sort indicators based on
#  - Whether it is not revoked
#  - Whether the indicator has "detection"
#  - Score (the higher the better)
#  - Confidence (the higher the better)
#  - valid_until is before now():
def indicator_sort_func(x):
    """Safe indicator sorting function with fallback values"""
    try:
        # Get values with safe fallbacks
        revoked = x.get('revoked', False)
        detection = x.get('x_opencti_detection', False)
        score = x.get('x_opencti_score', 0)
        confidence = x.get('confidence', 0)
        
        # Handle valid_until date parsing safely
        valid_until_str = x.get('valid_until', '')
        is_expired = False
        if valid_until_str:
            try:
                valid_until = datetime.strptime(valid_until_str, '%Y-%m-%dT%H:%M:%S.%fZ')
                is_expired = valid_until <= datetime.now()
            except ValueError:
                # If date parsing fails, treat as not expired
                is_expired = False
        
        return (revoked, not detection, -score, -confidence, is_expired)
    except Exception as e:
        logger.warning(f"Error sorting indicator: {e}")
        return (True, True, 0, 0, True)  # Put problematic indicators last

def sort_indicators(indicators):
    # In case there are several indicators, and since we will only extract
    # one, sort them based on !revoked, detection, score, confidence and
    # lastly expiry:
    return sorted(indicators, key=indicator_sort_func)

# Modify the indicator object so that it is more fit for opensearch (simplify
# deeply-nested lists etc.):
def modify_indicator(indicator):
    if indicator:
        # Simplify object lists for indicator labels and kill chain phases:
        simplify_objectlist(indicator, listKey = 'objectLabel', valueKey = 'value', newKey = 'labels')
        simplify_objectlist(indicator, listKey = 'killChainPhases', valueKey = 'kill_chain_name', newKey = 'killChainPhases')
        if 'externalReferences' in indicator:
            # Extract URIs from external references:
            simplify_objectlist(indicator, listKey = 'externalReferences', valueKey = 'url', newKey = 'externalReferences')

    return indicator

def indicator_link(indicator):
    return url.removesuffix('graphql') + 'dashboard/observations/indicators/{0}'.format(indicator['id'])

# Modify the observable object so that it is more fit for opensearch (simplify
# deeply-nested lists etc.):
def modify_observable(observable, indicators):
    """
    Modify the observable object so that it is more fit for opensearch (simplify
    deeply-nested lists etc.).

    This function takes an observable object and a list of indicator objects as
    input. It will generate a link to the observable, simplify the labels and
    external references, grab the most relevant indicator (using the
    indicator_sort_func), and generate a link to the indicator. Additionally, it
    will indicate in the alert that there were multiple indicators.

    :param observable: The observable object to modify
    :param indicators: A list of indicator objects to pick from
    :return: The modified observable object
    """
    # Generate a link to the observable:
    observable['observable_link'] = url.removesuffix('graphql') + 'dashboard/observations/observables/{0}'.format(observable['id'])

    # Extract URIs from external references:
    simplify_objectlist(observable, listKey = 'externalReferences', valueKey = 'url', newKey = 'externalReferences')
    # Convert list of file objects to list of file names:
    #simplify_objectlist(observable, listKey = 'importFiles', valueKey = 'name', newKey = 'importFiles')
    # Convert list of label objects to list of label names:
    simplify_objectlist(observable, listKey = 'objectLabel', valueKey = 'value', newKey = 'labels')

    # Grab the first indicator (already sorted to get the most relevant one):
    observable['indicator'] = next(iter(indicators), None)
    # Indicate in the alert that there were multiple indicators:
    observable['multipleIndicators'] = len(indicators) > 1
    # Generate a link to the indicator:
    if observable['indicator']:
        observable['indicator_link'] = indicator_link(observable['indicator'])

    modify_indicator(observable['indicator'])
    # Remove the original list of objects:
    del observable['indicators']
    # Remove the original list of relationships:
    del observable['stixCoreRelationships']

# Domain name–IP address releationships are not always up to date in a CTI
# database (naturally). If a DNS enrichment connector is used to create
# "resolves-to" relationship (or "related-to"), it may be worth looking up
# relationships to the observable, and if these objects have indicators, create
# an alert:
def relationship_with_indicators(node):
    """
    Analyzes the relationships of a given node to identify related indicators
    and enriches them with additional information.

    Parameters:
    node (dict): A dictionary containing a node with its STIX core relationships.

    Returns:
    dict or None: A dictionary containing the most relevant related indicator
    with its ID, type, relationship, value, a modified indicator object, and
    a link to the indicator if available. Returns None if no such indicator is found.

    The function processes the 'stixCoreRelationships' in the node, extracting
    indicators from related nodes. It modifies these indicators to include
    additional information relevant for alert generation. The indicators are
    sorted based on relevance criteria, and the most relevant one is returned.
    """

    related = []
    try:
        # Validate node structure first
        if 'stixCoreRelationships' not in node:
            return None
            
        relationships = node['stixCoreRelationships']
        if not isinstance(relationships, dict) or 'edges' not in relationships:
            return None
            
        if not isinstance(relationships['edges'], list):
            return None
            
        for relationship in relationships['edges']:
            if relationship['node']['related']['indicators']['edges']:
                # Create a list of the individual node objects in indicator edges:
                sorted_indicators = sort_indicators(list(map(lambda x:x['node'], relationship['node']['related']['indicators']['edges'])))
                top_indicator = next(iter(sorted_indicators), None)
                
                related.append(dict(
                    id=relationship['node']['related']['id'],
                    type=relationship['node']['type'],
                    relationship=relationship['node']['relationship_type'],
                    value=relationship['node']['related']['value'],
                    indicator=modify_indicator(top_indicator),
                    multipleIndicators=len(relationship['node']['related']['indicators']['edges']) > 1
                ))
                if related[-1]['indicator']:
                    related[-1]['indicator_link'] = indicator_link(related[-1]['indicator'])
    except KeyError:
        pass

    return next(iter(sorted(related, key=lambda x:indicator_sort_func(x['indicator']))), None)

def add_context(source_event, event):
    """
    Add context to an event based on a source event. The source event is
    expected to be a JSON object with keys 'id', 'rule', 'syscheck', 'data',
    and optionally 'alert' and 'win'. The function extracts relevant
    information from the source event and adds it to the event as a nested
    dictionary under the 'opencti' key.

    The information extracted from the source event includes the alert_id and
    rule_id, syscheck information (file, md5, sha1, sha256), data from the
    source event (in_iface, srcintf, src_ip, srcip, src_mac, srcmac, src_port,
    srcport, dest_ip, dstip, dest_mac, dstmac, dest_port, dstport, dstintf,
    proto, app_proto), DNS data (queryName, queryResults), alert data
    (action, category, signature, signature_id), Windows event data
    (queryName, queryResults, image), and audit execve data (success, key,
    uid, gid, euid, egid, exe, exit, pid).

    If the source event does not contain the expected keys, the function will
    not add any context to the event. If the source event contains invalid
    data, the function will log a warning.

    :param source_event: A JSON object containing the source event
    :param event: The event to add context to
    :return: The modified event with added context
    """
    logger.debug(f'Source Event: {source_event}')
    logger.debug(f'Event: {event}')
    try:
        # Initialize opencti and source dictionaries if not present
        if 'opencti' not in event:
            event['opencti'] = {}
        if 'source' not in event['opencti']:
            event['opencti']['source'] = {}

        # Add basic source information
        event['opencti']['source']['alert_id'] = source_event['id']
        event['opencti']['source']['rule_id'] = source_event['rule']['id']

        # Add syscheck information if present
        if 'syscheck' in source_event:
            event['opencti']['source']['file'] = source_event['syscheck']['path']
            event['opencti']['source']['md5'] = source_event['syscheck']['md5_after']
            event['opencti']['source']['sha1'] = source_event['syscheck']['sha1_after']
            event['opencti']['source']['sha256'] = source_event['syscheck']['sha256_after']

        # Process data field if present
        if 'data' in source_event:
            for key in ['in_iface', 'srcintf', 'src_ip', 'srcip', 'src_mac', 'srcmac', 'src_port', 'srcport',
                        'dest_ip', 'dstip', 'dst_mac', 'dstmac', 'dest_port', 'dstport', 'dstintf', 'proto', 'app_proto']:
                if key in source_event['data']:
                    event['opencti']['source'][key] = source_event['data'][key]

            # Process DNS data if present
            if packetbeat_dns(source_event):
                event['opencti']['source']['queryName'] = source_event['data']['dns']['question']['name']
                if 'answers' in source_event['data']['dns']:
                    event['opencti']['source']['queryResults'] = ';'.join(map(lambda x: x['data'], source_event['data']['dns']['answers']))

            # Process alert data if present and valid
            if 'alert' in source_event['data'] and isinstance(source_event['data']['alert'], dict):
                event['opencti']['source']['alert'] = {}  # Initialize alert dictionary
                for key in ['action', 'category', 'signature', 'signature_id']:
                    if key in source_event['data']['alert']:
                        event['opencti']['source']['alert'][key] = source_event['data']['alert'][key]
                logger.debug("Added alert context for alert_id %s: %s", source_event['id'], event['opencti']['source']['alert'])
            elif 'alert' in source_event['data']:
                logger.warning("Invalid 'alert' data in source_event['data'] for alert_id %s: %s",
                               source_event['id'], source_event['data']['alert'])
            else:
                logger.debug("No 'alert' key in source_event['data'] for alert_id %s", source_event['id'])

            # Process Windows event data if present
            if 'win' in source_event['data'] and 'eventdata' in source_event['data']['win']:
                for key in ['queryName', 'queryResults', 'image']:
                    if key in source_event['data']['win']['eventdata']:
                        event['opencti']['source'][key] = source_event['data']['win']['eventdata'][key]

            # Process audit execve data if present
            if 'audit' in source_event['data'] and 'execve' in source_event['data']['audit']:
                event['opencti']['source']['execve'] = ' '.join(source_event['data']['audit']['execve'][key] for key in sorted(source_event['data']['audit']['execve'].keys()))
                for key in ['success', 'key', 'uid', 'gid', 'euid', 'egid', 'exe', 'exit', 'pid']:
                    if key in source_event['data']['audit']:
                        event['opencti']['source'][key] = source_event['data']['audit'][key]

        logger.debug("Successfully added context for alert_id: %s", source_event['id'])
    except Exception as e:
        logger.error("Error adding context for alert_id %s: %s", source_event.get('id', 'unknown'), str(e))

def send_event(msg: Dict[str, Any], agent: Optional[Dict[str, Any]] = None) -> None:
    """Send an event to the Wazuh Manager with improved error handling"""
    try:
        if not agent or agent.get('id') == '000':
            event_string = f'1:opencti:{json.dumps(msg, separators=(",", ":"))}'
        else:
            agent_info = f"[{agent['id']}] ({agent['name']}) {agent.get('ip', 'any')}"
            event_string = f'1:{agent_info}->opencti:{json.dumps(msg, separators=(",", ":"))}'
        
        logger.debug(f"Sending Event: {event_string[:200]}...")  # Truncate for log
        
        # Check if socket exists before attempting connection
        if not os.path.exists(socket_addr):
            logger.warning(f"Wazuh socket {socket_addr} does not exist - logging event instead")
            logger.info(f"Event would be sent: {event_string[:500]}...")
            return
        
        with socket(AF_UNIX, SOCK_DGRAM) as sock:
            sock.settimeout(5.0)  # Set socket timeout
            sock.connect(socket_addr)
            sock.send(event_string.encode('utf-8'))
            logger.debug("Event sent successfully")
            
    except (OSError, ConnectionError) as e:
        logger.error(f"Socket error sending event: {e}")
        logger.info(f"Failed event content: {event_string[:300]}...")
        # Don't raise in production - log and continue
    except Exception as e:
        logger.error(f"Unexpected error sending event: {e}")
        # Don't raise in production - log and continue

def send_error_event(msg, agent = None):
    send_event({'integration': 'opencti', 'opencti': {
        'error': msg,
        'event_type': 'error',
        }}, agent)

# Construct a stix pattern for a single IP address, either IPv4 or IPv6:
def ind_ip_pattern(string):
    if ipaddress.ip_address(string).version == 6:
        return f"[ipv6-addr:value = '{string}']"
    else:
        return f"[ipv4-addr:value = '{string}']"

# Return the value of the first key argument that exists in within:
def oneof(*keys, within):
    return next((within[key] for key in keys if key in within), None)

def parse_wazuh_timestamp(timestamp_str: str) -> Optional[datetime]:
    """
    Parse Wazuh timestamp with multiple format support including local timezones
    Returns parsed datetime object or None if parsing fails
    """
    if not timestamp_str:
        return None
        
    timestamp_formats = [
        # ISO format with any timezone (handles +0700, +00:00, etc.)
        lambda ts: datetime.fromisoformat(ts),
        # ISO format with Z (UTC)
        lambda ts: datetime.fromisoformat(ts.replace('Z', '+00:00')),
        # ISO format without timezone (assume UTC)
        lambda ts: datetime.fromisoformat(ts + '+00:00') if not ts.endswith(('Z', '+00:00', '-00:00')) and '+' not in ts[-6:] and '-' not in ts[-6:] else datetime.fromisoformat(ts.replace('Z', '+00:00')),
        # Wazuh specific format with milliseconds and Z: 2024-01-01T12:00:00.000Z
        lambda ts: datetime.strptime(ts.replace('Z', ''), '%Y-%m-%dT%H:%M:%S.%f'),
        # Wazuh format without milliseconds and Z: 2024-01-01T12:00:00Z
        lambda ts: datetime.strptime(ts.replace('Z', ''), '%Y-%m-%dT%H:%M:%S'),
    ]
    
    for fmt_func in timestamp_formats:
        try:
            return fmt_func(timestamp_str)
        except (ValueError, TypeError):
            continue
    
    return None

def validate_wazuh_log_structure(alert: Dict[str, Any]) -> bool:
    """Validate Wazuh 4.11 log structure compatibility"""
    required_fields = ['id', 'rule', 'agent']
    
    try:
        for field in required_fields:
            if field not in alert:
                logger.warning(f"Missing required field: {field}")
                return False
        
        # Validate rule structure (Wazuh 4.11 specific)
        rule = alert['rule']
        if not isinstance(rule, dict):
            logger.warning("Invalid rule structure - not a dict")
            return False
            
        # Required rule fields in Wazuh 4.11
        required_rule_fields = ['id', 'level', 'description']
        for field in required_rule_fields:
            if field not in rule:
                logger.warning(f"Missing required rule field: {field}")
                return False
                
        # Validate groups field exists
        if 'groups' not in rule or not isinstance(rule['groups'], list):
            logger.warning("Missing or invalid rule.groups field")
            return False
            
        # Validate agent structure (Wazuh 4.11 specific)
        agent = alert['agent']
        if not isinstance(agent, dict):
            logger.warning("Invalid agent structure - not a dict")
            return False
            
        # Required agent fields in Wazuh 4.11
        required_agent_fields = ['id', 'name']
        for field in required_agent_fields:
            if field not in agent:
                logger.warning(f"Missing required agent field: {field}")
                return False
                
        # Validate timestamp format (Wazuh 4.11)
        if 'timestamp' in alert:
            timestamp = alert['timestamp']
            
            parsed_timestamp = parse_wazuh_timestamp(timestamp)
            if parsed_timestamp is None:
                logger.warning(f"Timestamp parsing failed for: '{timestamp}' "
                             f"(Expected ISO8601: +0700, Z, +00:00, etc.)")
                # Continue processing despite timestamp issues
            # Only log successful parsing in debug mode to reduce log volume
                
        logger.debug("Wazuh 4.11 log structure validation passed")
        return True
    except Exception as e:
        logger.error(f"Log structure validation failed: {e}")
        return False

def validate_opencti_compatibility(response_data: Dict[str, Any]) -> bool:
    """Validate OpenCTI 6.7.11 response structure compatibility"""
    try:
        # Check for GraphQL errors first
        if 'errors' in response_data:
            logger.error(f"GraphQL errors in OpenCTI response: {response_data['errors']}")
            return False
            
        if 'data' not in response_data:
            logger.warning("Missing 'data' field in OpenCTI response")
            return False
            
        data = response_data['data']
        
        # Check for expected GraphQL structure (OpenCTI 6.7.11)
        expected_keys = ['indicators', 'stixCyberObservables']
        for key in expected_keys:
            if key not in data:
                logger.warning(f"Missing expected field in OpenCTI response: {key}")
                return False
                
            # Validate GraphQL edges structure
            if not isinstance(data[key], dict):
                logger.warning(f"Invalid structure for {key} in OpenCTI response - not a dict")
                return False
                
            if 'edges' not in data[key]:
                logger.warning(f"Missing 'edges' in {key} in OpenCTI response")
                return False
                
            if not isinstance(data[key]['edges'], list):
                logger.warning(f"Invalid edges structure for {key} - not a list")
                return False
                
            # Validate pageInfo structure (OpenCTI 6.7.11)
            if 'pageInfo' not in data[key]:
                logger.warning(f"Missing pageInfo for {key} in OpenCTI response")
                # Don't fail for missing pageInfo, it's not critical
                
        # Validate indicator nodes structure if present
        if data['indicators']['edges']:
            for edge in data['indicators']['edges'][:1]:  # Check first one only
                if 'node' not in edge:
                    logger.warning("Invalid indicator edge structure - missing node")
                    return False
                node = edge['node']
                required_indicator_fields = ['id', 'pattern']
                for field in required_indicator_fields:
                    if field not in node:
                        logger.debug(f"Missing indicator field: {field} (may be normal)")
                        
        # Validate observable nodes structure if present
        if data['stixCyberObservables']['edges']:
            for edge in data['stixCyberObservables']['edges'][:1]:  # Check first one only
                if 'node' not in edge:
                    logger.warning("Invalid observable edge structure - missing node")
                    return False
                node = edge['node']
                if 'id' not in node:
                    logger.warning("Missing observable id")
                    return False
                    
        logger.debug("OpenCTI 6.7.11 response structure validation passed")
        return True
    except Exception as e:
        logger.error(f"OpenCTI compatibility validation failed: {e}")
        return False

def normalize_wazuh_fields(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize Wazuh 4.11 field names for better compatibility"""
    normalized = alert.copy()
    
    try:
        # Normalize common field variations in Wazuh 4.11
        if 'data' in normalized:
            data = normalized['data']
            
            # Normalize IP address fields (Wazuh 4.11 variations)
            if 'srcip' in data and 'src_ip' not in data:
                data['src_ip'] = data['srcip']
            if 'dstip' in data and 'dest_ip' not in data:
                data['dest_ip'] = data['dstip']
            if 'destination_ip' in data and 'dest_ip' not in data:
                data['dest_ip'] = data['destination_ip']
            if 'source_ip' in data and 'src_ip' not in data:
                data['src_ip'] = data['source_ip']
                
            # Normalize port fields (Wazuh 4.11 variations)
            if 'srcport' in data and 'src_port' not in data:
                data['src_port'] = data['srcport']
            if 'dstport' in data and 'dest_port' not in data:
                data['dest_port'] = data['dstport']
            if 'destination_port' in data and 'dest_port' not in data:
                data['dest_port'] = data['destination_port']
            if 'source_port' in data and 'src_port' not in data:
                data['src_port'] = data['source_port']
                
            # Normalize MAC address fields
            if 'srcmac' in data and 'src_mac' not in data:
                data['src_mac'] = data['srcmac']
            if 'dstmac' in data and 'dest_mac' not in data:
                data['dest_mac'] = data['dstmac']
                
            # Normalize protocol fields
            if 'protocol' in data and 'proto' not in data:
                data['proto'] = data['protocol']
                
            # Normalize Windows event data (Sysmon in Wazuh 4.11)
            if 'win' in data and 'eventdata' in data['win']:
                eventdata = data['win']['eventdata']
                
                # Normalize Sysmon field names
                field_mappings = {
                    'DestinationIp': 'destinationIp',
                    'DestinationPort': 'destinationPort',
                    'SourceIp': 'sourceIp',
                    'SourcePort': 'sourcePort',
                    'QueryName': 'queryName',
                    'QueryResults': 'queryResults',
                    'Hashes': 'hashes',
                    'Image': 'image'
                }
                
                for old_field, new_field in field_mappings.items():
                    if old_field in eventdata and new_field not in eventdata:
                        eventdata[new_field] = eventdata[old_field]
                        
            # Normalize DNS query structure (Wazuh 4.11)
            if 'dns' in data and 'query' in data['dns']:
                # Ensure query is a list
                if not isinstance(data['dns']['query'], list):
                    data['dns']['query'] = [data['dns']['query']]
                    
                # Normalize rrname field
                for query in data['dns']['query']:
                    if isinstance(query, dict):
                        if 'rrname' not in query and 'name' in query:
                            query['rrname'] = query['name']
                        if 'query_name' in query and 'rrname' not in query:
                            query['rrname'] = query['query_name']
                            
        logger.debug("Field normalization completed successfully")
        return normalized
    except Exception as e:
        logger.error(f"Field normalization failed: {e}")
        return alert

def query_opencti(alert, url, token):
    """
    Construct a query to the OpenCTI API and return a list of alerts based on the
    response. The query is constructed based on the group names in the alert.
    Currently, the following group names are processed:

    - ids: Look up either dest or source IP, whichever is public
    - sysmon_event3: Look up either dest or source IP, whichever is public
    - sysmon_event22: Look up domain names in DNS queries, along with the results
    - syscheck_file: Look up sha256 hashes for files added to the system or files
      that have been modified
    - osquery_file: Look up sha256 hashes in columns of any osqueries
    - audit_command: Extract any command line arguments that looks vaguely like a
      URL (starts with 'http')

    :param alert: The alert to process
    :param url: The URL of the OpenCTI API
    :param token: The API token for the OpenCTI API
    :return: A list of alerts based on the response from the OpenCTI API
    """
    # The OpenCTI graphql query is filtering on a key and a list of values. By
    # default, this key is "value", unless set to "hashes.SHA256":
    filter_key='value'
    groups = alert['rule']['groups']

    # TODO: Look up registry keys/values? No such observables in OpenCTI yet from any sources

    # In case a key or index lookup fails, catch this and gracefully exit. Wrap
    # logic in a try–catch:
    try:
        # For any sysmon event that provides a sha256 hash (matches the group
        # name regex):
        if any(True for _ in filter(sha256_sysmon_event_regex.match, groups)):
            filter_key='hashes.SHA256'
            # It is not a 100 % guaranteed that there is a (valid) sha256 hash
            # present in the metadata. Quit if no hash is found:
            match = regex_file_hash.search(alert['data']['win']['eventdata']['hashes'])
            if match:
                filter_values = [match.group(0)]
                ind_filter = [f"[file:hashes.'SHA-256' = '{match.group(0)}']"]
            else:
                sys.exit()
        # Sysmon event 3 contains IP addresses, which will be queried:
        elif any (True for _ in filter(sysmon_event3_regex.match, groups)):
            filter_values = [alert['data']['win']['eventdata']['destinationIp']]
            ind_filter = [ind_ip_pattern(filter_values[0])]
            if not ipaddress.ip_address(filter_values[0]).is_global:
                sys.exit()
        # Groups that contain IP addresses or domains for threat intelligence lookup.
        # This includes IDS alerts, attack detection, web security, threat intel, and various security groups:
        elif any(group in groups for group in [
            'ids', 'attack', 'web', 'gambling', 'web_scan', 'recon', 'wordpress', 
            'rce', 'web_attack', 'threat_intel', 'opencti', 'opencti_alert', 
            'linux', 'webshell', 'ossec'
        ]):
            # Initialize variables
            filter_values = []
            ind_filter = []
            
            # Check for Packetbeat DNS query first (highest priority)
            if packetbeat_dns(alert):
                # Packetbeat DNS processing
                query_name = alert['data']['dns']['question']['name']
                addrs = filter_packetbeat_dns(alert['data']['dns']['answers']) if 'answers' in alert['data']['dns'] else []
                filter_values = [query_name] + addrs
                ind_filter = [f"[domain-name:value = '{query_name}']", f"[hostname:value = '{query_name}']"] + list(map(lambda a: ind_ip_pattern(a), addrs))
                logger.debug(f'Packetbeat DNS query: {query_name}, addresses: {addrs}')
                
            # Check for general DNS data in alert (medium priority)
            elif 'dns' in alert['data'] and 'query' in alert['data']['dns'] and alert['data']['dns']['query']:
                # Extract rrname from DNS query
                rrname = alert['data']['dns']['query'][0].get('rrname', '')
                logger.debug(f'Extract rrname to check: {rrname}')
                
                # Look up either dest or source IP, whichever is public
                public_ip = next(filter(lambda x: x and ipaddress.ip_address(x).is_global, [
                    oneof('dest_ip', 'dstip', within=alert['data']),
                    oneof('src_ip', 'srcip', within=alert['data'])
                ]), None)
                
                # Build filter values and indicators
                if public_ip and rrname:
                    filter_values = [public_ip, rrname]
                    ind_filter = [ind_ip_pattern(public_ip)]
                    ind_filter.extend([
                        f"[domain-name:value = '{rrname}']",
                        f"[hostname:value = '{rrname}']"
                    ])
                elif rrname:
                    filter_values = [rrname]
                    ind_filter = [
                        f"[domain-name:value = '{rrname}']",
                        f"[hostname:value = '{rrname}']"
                    ]
                elif public_ip:
                    filter_values = [public_ip]
                    ind_filter = [ind_ip_pattern(public_ip)]
                    
                logger.debug(f'DNS query processing - IP: {public_ip}, Domain: {rrname}')
                
            # Fall back to IP-only processing (lowest priority)
            else:
                # Look up either dest or source IP, whichever is public
                public_ip = next(filter(lambda x: x and ipaddress.ip_address(x).is_global, [
                    oneof('dest_ip', 'dstip', within=alert['data']),
                    oneof('src_ip', 'srcip', within=alert['data'])
                ]), None)
                
                if public_ip:
                    filter_values = [public_ip]
                    ind_filter = [ind_ip_pattern(public_ip)]
                    logger.debug(f'IP-only processing: {public_ip}')
                
            # Validate that we have something to query
            if not filter_values or not any(filter_values) or not ind_filter:
                logger.debug('No valid indicators found for IDS alert, skipping')
                sys.exit()

        # Look up domain names in DNS queries (sysmon event 22), along with the
        # results (if they're IPv4/IPv6 addresses (A/AAAA records)):
        elif any(True for _ in filter(sysmon_event22_regex.match, groups)):
            query = alert['data']['win']['eventdata']['queryName']
            results = format_dns_results(alert['data']['win']['eventdata']['queryResults'])
            filter_values = [query] + results
            ind_filter = [f"[domain-name:value = '{filter_values[0]}']", f"[hostname:value = '{filter_values[0]}']"] + list(map(lambda a: ind_ip_pattern(a), results))
        # Look up sha256 hashes for files added to the system or files that have been modified.
        # Support various syscheck and file monitoring groups:
        elif any(group in groups for group in ['syscheck_file', 'syscheck', 'file_monitoring']) and any(x in groups for x in ['syscheck_entry_added', 'syscheck_entry_modified']):
            filter_key = 'hashes.SHA256'
            filter_values = [alert['syscheck']['sha256_after']]
            ind_filter = [f"[file:hashes.'SHA-256' = '{filter_values[0]}']"]
        # Look up sha256 hashes in columns of any osqueries:
        # Currently, only osquery_file is defined in wazuh_manager.conf, but add 'osquery' for future use(?):
        elif any(x in groups for x in ['osquery', 'osquery_file']):
            filter_key = 'hashes.SHA256'
            filter_values = [alert['data']['osquery']['columns']['sha256']]
            ind_filter = [f"[file:hashes.'SHA-256' = '{filter_values[0]}']"]
        elif 'audit_command' in groups:
            # Extract any command line arguments that looks vaguely like a URL (starts with 'http'):
            filter_values = [val for val in alert['data']['audit']['execve'].values() if val.startswith('http')]
            ind_filter = list(map(lambda x: f"[url:value = '{x}']", filter_values))
            if not filter_values:
                sys.exit()
        # Handle rootcheck alerts - look for file paths or suspicious indicators
        elif 'rootcheck' in groups:
            # Extract file paths, IPs, or URLs from rootcheck alerts
            filter_values = []
            ind_filter = []
            
            # Try to extract IPs from rootcheck data
            if 'data' in alert:
                data_str = str(alert['data'])
                # Simple IP extraction from rootcheck messages
                import re
                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                found_ips = re.findall(ip_pattern, data_str)
                
                for ip in found_ips:
                    try:
                        if ipaddress.ip_address(ip).is_global:
                            filter_values.append(ip)
                            ind_filter.append(ind_ip_pattern(ip))
                    except ValueError:
                        continue
            
            if not filter_values:
                sys.exit()
        # Handle YARA alerts - look for file hashes or suspicious indicators  
        elif 'yara' in groups:
            # Try to extract file hashes from YARA alerts
            filter_key = 'hashes.SHA256'
            filter_values = []
            ind_filter = []
            
            # Look for SHA256 hashes in YARA alert data
            if 'data' in alert:
                data_str = str(alert['data'])
                hash_matches = regex_file_hash.findall(data_str)
                if hash_matches:
                    filter_values = [hash_matches[0]]  # Take first found hash
                    ind_filter = [f"[file:hashes.'SHA-256' = '{hash_matches[0]}']"]
            
            # Fallback: look for IPs if no hashes found
            if not filter_values and 'data' in alert:
                data_str = str(alert['data'])
                import re
                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                found_ips = re.findall(ip_pattern, data_str)
                
                for ip in found_ips:
                    try:
                        if ipaddress.ip_address(ip).is_global:
                            filter_key = 'value'  # Reset to default for IPs
                            filter_values.append(ip)
                            ind_filter.append(ind_ip_pattern(ip))
                            break
                    except ValueError:
                        continue
            
            if not filter_values:
                sys.exit()
        # Nothing to do:
        else:
            sys.exit()

    # Don't treat a non-existent index or key as an error. If they don't exist,
    # there is certainly no alert to make. Just quit:
    except IndexError:
        sys.exit()
    except KeyError:
        sys.exit()

    query_headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {token}',
        'Accept': '*/*'
    }
    # Look for hashes, addresses and domain names is as many places as
    # possible, and return as much information as possible.
    api_json_body={'query':
            '''
            fragment Labels on StixCoreObject {
              objectLabel {
                value
              }
            }

            fragment Object on StixCoreObject {
              id
              type: entity_type
              created_at
              updated_at
              createdBy {
                ... on Identity {
                  id
                  standard_id
                  identity_class
                  name
                }
                ... on Organization {
                  x_opencti_organization_type
                  x_opencti_reliability
                }
                ... on Individual {
                  x_opencti_firstname
                  x_opencti_lastname
                }
              }
              ...Labels
              externalReferences {
                edges {
                  node {
                    url
                  }
                }
              }
            }

            fragment IndShort on Indicator {
              id
              name
              valid_until
              revoked
              confidence
              x_opencti_score
              x_opencti_detection
              indicator_types
              x_mitre_platforms
              pattern_type
              pattern
              ...Labels
              killChainPhases {
                kill_chain_name
              }
            }

            fragment IndLong on Indicator {
              ...Object
              ...IndShort
            }

            fragment Indicators on StixCyberObservable {
              indicators {
                edges {
                  node {
                    ...IndShort
                  }
                }
              }
            }

            fragment PageInfo on PageInfo {
              startCursor
              endCursor
              hasNextPage
              hasPreviousPage
              globalCount
            }

            fragment NameRelation on StixObjectOrStixRelationshipOrCreator {
              ... on DomainName {
                id
                value
                ...Indicators
              }
              ... on Hostname {
                id
                value
                ...Indicators
              }
            }

            fragment AddrRelation on StixObjectOrStixRelationshipOrCreator {
              ... on IPv4Addr {
                id
                value
                ...Indicators
              }
              ... on IPv6Addr {
                id
                value
                ...Indicators
              }
            }

            query IoCs($obs: FilterGroup, $ind: FilterGroup) {
              indicators(filters: $ind, first: 10) {
                edges {
                  node {
                    ...IndLong
                  }
                }
                pageInfo {
                  ...PageInfo
                }
              }
              stixCyberObservables(filters: $obs, first: 10) {
                edges {
                  node {
                    ...Object
                    observable_value
                    x_opencti_description
                    x_opencti_score
                    ...Indicators
                    ... on DomainName {
                      value
                      stixCoreRelationships(
                        toTypes: ["IPv4-Addr", "IPv6-Addr", "Domain-Name", "Hostname"]
                      ) {
                        edges {
                          node {
                            type: toType
                            relationship_type
                            related: to {
                              ...AddrRelation
                              ...NameRelation
                            }
                          }
                        }
                      }
                    }
                    ... on Hostname {
                      value
                      stixCoreRelationships(
                        toTypes: ["IPv4-Addr", "IPv6-Addr", "Domain-Name", "Hostname"]
                      ) {
                        edges {
                          node {
                            type: toType
                            relationship_type
                            related: to {
                              ...AddrRelation
                              ...NameRelation
                            }
                          }
                        }
                      }
                    }
                    ... on Url {
                      value
                      stixCoreRelationships(
                        toTypes: ["IPv4-Addr", "IPv6-Addr", "Domain-Name", "Hostname"]
                      ) {
                        edges {
                          node {
                            type: toType
                            relationship_type
                            related: to {
                              ...AddrRelation
                              ...NameRelation
                            }
                          }
                        }
                      }
                    }
                    ... on IPv4Addr {
                      value
                      stixCoreRelationships(fromTypes: ["Domain-Name", "Hostname"]) {
                        edges {
                          node {
                            type: fromType
                            relationship_type
                            related: from {
                              ...NameRelation
                            }
                          }
                        }
                      }
                    }
                    ... on IPv6Addr {
                      value
                      stixCoreRelationships(fromTypes: ["Domain-Name", "Hostname"]) {
                        edges {
                          node {
                            type: fromType
                            relationship_type
                            related: from {
                              ...NameRelation
                            }
                          }
                        }
                      }
                    }
                    ... on StixFile {
                      extensions
                      size
                      name
                      x_opencti_additional_names
                    }
                  }
                }
                pageInfo {
                  ...PageInfo
                }
              }
            }
            ''' , 'variables': {
                    'obs': {
                        "mode": "or",
                        "filterGroups": [],
                        "filters": [{"key": filter_key, "values": filter_values}]
                    },
                    'ind': {
                        "mode": "and",
                        "filterGroups": [],
                        "filters": [
                            {"key": "pattern_type", "values": ["stix"]},
                            {"mode": "or", "key": "pattern", "values": ind_filter},
                        ]
                    }
                    }}
    debug('# Query:')
    debug(api_json_body)

    new_alerts = []
    try:
        increment_request_counter()
        session = get_session()
        response = session.post(
            url, 
            headers=query_headers, 
            json=api_json_body,
            timeout=REQUEST_TIMEOUT
        )
        
        # Check HTTP status for production
        if response.status_code >= 400:
            increment_error_counter()
            logger.error(f"OpenCTI API returned HTTP {response.status_code}: {response.text[:200]}")
            send_error_event(f'OpenCTI API HTTP error {response.status_code}', alert['agent'])
            sys.exit(1)
    # Create an alert if the OpenCTI service cannot be reached:
    except (ConnectionError, Timeout) as e:
        increment_error_counter()
        logger.error(f'Failed to connect to {url}: {e}')
        send_error_event(f'Failed to connect to the OpenCTI API: {e}', alert['agent'])
        sys.exit(1)
    except RequestException as e:
        increment_error_counter()
        logger.error(f'Request failed to {url}: {e}')
        send_error_event(f'OpenCTI API request failed: {e}', alert['agent'])
        sys.exit(1)

    try:
        response_data = response.json()
    except json.decoder.JSONDecodeError as e:
        increment_error_counter()
        logger.error(f'Failed to parse JSON response from API: {e}')
        logger.error(f'Response content: {response.text[:500]}...')
        send_error_event('Failed to parse response from OpenCTI API', alert['agent'])
        sys.exit(1)
        
    # Validate OpenCTI response structure
    if not validate_opencti_compatibility(response_data):
        increment_error_counter()
        logger.error("Incompatible OpenCTI response structure")
        send_error_event('Incompatible OpenCTI response structure', alert['agent'])
        sys.exit(1)

    debug('# Response:')
    debug(response_data)
    logger.info(f"Received {len(response_data.get('data', {}).get('indicators', {}).get('edges', []))} indicators and {len(response_data.get('data', {}).get('stixCyberObservables', {}).get('edges', []))} observables from OpenCTI")

    # Sort indicators based on a number of factors in order to prioritise them
    # in case many are returned:
    direct_indicators = sorted(
            # Extract the indicator objects (nodes) from the indicator list in
            # the response:
            list(map(lambda x:x['node'], response_data['data']['indicators']['edges'])),
            key=indicator_sort_func)
    # As opposed to indicators for observables, create an alert for every
    # indicator (limited by max_ind_alerts and the fixed limit in the query
    # (see "first: X")):
    for indicator in direct_indicators[:MAX_IND_ALERTS]:
        new_alert = {'integration': 'opencti', 'opencti': {
            'indicator': modify_indicator(indicator),
            'indicator_link': indicator_link(indicator),
            'query_key': filter_key,
            'query_values': ';'.join(ind_filter),
            'event_type': 'indicator_pattern_match' if indicator.get('pattern', '') in ind_filter else 'indicator_partial_pattern_match',
            }}
        add_context(alert, new_alert)
        new_alerts.append(remove_empties(new_alert))

    for edge in response_data['data']['stixCyberObservables']['edges']:
        node = edge['node']

        # Create a list of the individual node objects in indicator edges:
        indicators = sort_indicators(list(map(lambda x:x['node'], node['indicators']['edges'])))
        # Get related obsverables (typically between IP addresses and domain
        # names) if they have indicators (retrieve only one indicator):
        related_obs_w_ind = relationship_with_indicators(node)

        # Remove indicators already found directly in the indicator query:
        if indicators:
            indicators = [i for i in indicators if i['id'] not in [di['id'] for di in direct_indicators]]
        if related_obs_w_ind and related_obs_w_ind['indicator']['id'] in [di['id'] for di in direct_indicators]:
            related_obs_w_ind = None

        # If the observable has no indicators, ignore it:
        if not indicators and not related_obs_w_ind:
            # TODO: Create event for this?
            logger.debug(f'# Observable found ({node["id"]}), but it has no indicators')
            continue

        new_alert = {'integration': 'opencti', 'opencti': edge['node']}
        new_alert['opencti']['related'] = related_obs_w_ind
        new_alert['opencti']['query_key'] = filter_key
        new_alert['opencti']['query_values'] = ';'.join(filter_values)
        new_alert['opencti']['event_type'] = 'observable_with_indicator' if indicators else 'observable_with_related_indicator'

        modify_observable(new_alert['opencti'], indicators)

        add_context(alert, new_alert)
        # Remove all nulls, empty lists and objects, and empty strings:
        new_alerts.append(remove_empties(new_alert))

    return new_alerts

if __name__ == '__main__':
    try:
        if len(sys.argv) >= 4:
            debug('{0} {1} {2} {3}'.format(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else ''), do_log = True)
            logger.debug('{0} {1} {2} {3}'.format(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else ''))
        else:
            logger.debug('Incorrect arguments: {0}'.format(' '.join(sys.argv)))
            sys.exit(1)

        debug_enabled = len(sys.argv) > 4 and sys.argv[4] == 'debug'

        main(sys.argv)
    except Exception as e:
        debug(str(e), do_log = True)
        debug(traceback.format_exc(), do_log = True)
        raise
