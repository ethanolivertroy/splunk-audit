#!/usr/bin/env python3
"""Test script to verify installation and imports"""

def test_imports():
    """Test that all required modules can be imported"""
    print("Testing imports...")
    
    try:
        import splunklib.client
        print("✓ splunklib imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import splunklib: {e}")
        
    try:
        import yaml
        print("✓ yaml imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import yaml: {e}")
        
    try:
        import click
        print("✓ click imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import click: {e}")
        
    try:
        import jinja2
        print("✓ jinja2 imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import jinja2: {e}")
        
    try:
        from modules.api_client import SplunkAPIClient
        print("✓ Local modules imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import local modules: {e}")
        
    print("\nConfiguration files check:")
    import os
    
    files_to_check = [
        'config/checks.yaml',
        'config/severity_mapping.yaml',
        'splunk_compliance.py'
    ]
    
    for file in files_to_check:
        if os.path.exists(file):
            print(f"✓ {file} exists")
        else:
            print(f"✗ {file} not found")


if __name__ == "__main__":
    print("Splunk Compliance Checker - Installation Test")
    print("=" * 50)
    test_imports()
    print("\nInstallation test complete!")
    print("\nTo run the compliance checker:")
    print("python splunk_compliance.py --help")