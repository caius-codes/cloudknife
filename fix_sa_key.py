#!/usr/bin/env python3
"""
Fix malformed GCP service account JSON keys.

This script fixes private keys that are missing newlines,
which causes "Invalid private key" errors.

Usage:
    python fix_sa_key.py path/to/key.json
    python fix_sa_key.py path/to/key.json --output fixed-key.json
"""

import json
import sys
from pathlib import Path


def fix_private_key(key_str: str) -> str:
    """
    Fix a malformed private key by adding proper newlines.

    PEM private keys should have:
    - -----BEGIN PRIVATE KEY-----
    - Base64 content split into 64-character lines
    - -----END PRIVATE KEY-----
    """
    # Check if already properly formatted
    if '\n' in key_str and '-----BEGIN PRIVATE KEY-----\n' in key_str:
        return key_str

    # Remove existing BEGIN/END markers and whitespace
    key_content = (
        key_str
        .replace('-----BEGIN PRIVATE KEY-----', '')
        .replace('-----END PRIVATE KEY-----', '')
        .replace('\n', '')
        .replace('\r', '')
        .strip()
    )

    # Split into 64-character lines
    lines = [key_content[i:i+64] for i in range(0, len(key_content), 64)]

    # Rebuild with proper format
    return '-----BEGIN PRIVATE KEY-----\n' + '\n'.join(lines) + '\n-----END PRIVATE KEY-----\n'


def main():
    if len(sys.argv) < 2:
        print("Usage: python fix_sa_key.py <path-to-sa-key.json> [--output <output-path>]")
        print("\nExample:")
        print("  python fix_sa_key.py deploy-credentials.json")
        print("  python fix_sa_key.py key.json --output fixed-key.json")
        sys.exit(1)

    input_path = Path(sys.argv[1])

    # Check for --output flag
    output_path = input_path
    if '--output' in sys.argv:
        try:
            output_idx = sys.argv.index('--output')
            output_path = Path(sys.argv[output_idx + 1])
        except (ValueError, IndexError):
            print("Error: --output flag requires a path")
            sys.exit(1)

    if not input_path.exists():
        print(f"Error: File not found: {input_path}")
        sys.exit(1)

    # Load the JSON
    try:
        with open(input_path, 'r') as f:
            key_data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON: {e}")
        sys.exit(1)

    # Check if it's a service account key
    if key_data.get('type') != 'service_account':
        print("Error: This doesn't appear to be a service account JSON key")
        print(f"  Expected type='service_account', got type='{key_data.get('type')}'")
        sys.exit(1)

    # Check if private_key exists
    if 'private_key' not in key_data:
        print("Error: No 'private_key' field found in JSON")
        sys.exit(1)

    # Fix the private key
    original_key = key_data['private_key']
    fixed_key = fix_private_key(original_key)

    if original_key == fixed_key:
        print("✓ Private key is already properly formatted")
        sys.exit(0)

    # Update the key
    key_data['private_key'] = fixed_key

    # Save to output file
    with open(output_path, 'w') as f:
        json.dump(key_data, f, indent=2)

    if input_path == output_path:
        print(f"✓ Fixed private key formatting in: {output_path}")
    else:
        print(f"✓ Fixed key saved to: {output_path}")
        print(f"  (Original preserved at: {input_path})")

    print("\nYou can now use this key with CloudKnife:")
    print(f"  set_credentials {output_path}")


if __name__ == '__main__':
    main()
