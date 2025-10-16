#!/usr/bin/env python3
"""
Setup and Launch Script for Steganography Tool
This script will install required dependencies and launch the application.
"""

import subprocess
import sys
import os

def install_requirements():
    """Install required packages."""
    print("Installing required packages...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✓ All dependencies installed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ Error installing dependencies: {e}")
        return False
    except FileNotFoundError:
        print("✗ pip not found. Please ensure Python and pip are properly installed.")
        return False

def launch_app():
    """Launch the steganography application."""
    try:
        print("Launching Steganography Tool...")
        import steganography_tool
        steganography_tool.main()
    except ImportError as e:
        print(f"✗ Error importing steganography_tool: {e}")
        return False
    except Exception as e:
        print(f"✗ Error launching application: {e}")
        return False

def main():
    """Main setup and launch function."""
    print("=" * 50)
    print("Steganography Tool - Setup & Launch")
    print("=" * 50)
    
    # Check if requirements.txt exists
    if not os.path.exists("requirements.txt"):
        print("✗ requirements.txt not found!")
        input("Press Enter to exit...")
        return
    
    # Install dependencies
    if not install_requirements():
        input("Press Enter to exit...")
        return
    
    print("\n" + "=" * 50)
    print("Starting application...")
    print("=" * 50)
    
    # Launch the application
    launch_app()

if __name__ == "__main__":
    main()