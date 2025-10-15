#!/usr/bin/env python3
"""
File Encryption Tool - GUI Launcher
Operating Systems Project

This script starts the graphical user interface for the file encryption tool.
"""

import sys
import os

def check_requirements():
    """Check if all required modules are available"""
    try:
        import tkinter
        from encryption_module import FileEncryptor
        return True
    except ImportError as e:
        print(f"❌ Missing requirement: {e}")
        print("\n🔧 To fix this:")
        print("1. Make sure tkinter is installed (usually comes with Python)")
        print("2. Make sure encryption_module.py is in the same directory")
        return False

def main():
    """Main launcher function"""
    print("🔐 File Encryption Tool - GUI Launcher")
    print("=" * 50)
    
    # Check requirements
    if not check_requirements():
        input("\n❌ Press Enter to exit...")
        return
    
    print("✅ All requirements satisfied")
    print("🚀 Starting GUI application...")
    
    try:
        # Import and run GUI
        from gui import main as gui_main
        gui_main()
    
    except KeyboardInterrupt:
        print("\n👋 Application interrupted by user")
    except Exception as e:
        print(f"\n❌ An error occurred: {e}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
