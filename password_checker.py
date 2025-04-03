#!/usr/bin/env python3
"""Password Strength Checker - Evaluates password strength based on multiple criteria."""

import re
import argparse
import logging
import configparser
import sys
from pathlib import Path

def setup_logging(log_file):
    """Configure logging to file and console."""
    try:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
    except Exception as e:
        print(f"Failed to setup logging: {e}", file=sys.stderr)
        sys.exit(1)

def load_config(config_file):
    """Load settings from configuration file."""
    config = configparser.ConfigParser()
    try:
        if not config.read(config_file):
            raise FileNotFoundError(f"Config file {config_file} not found")
        return config['Settings']
    except Exception as e:
        logging.error(f"Failed to load config: {e}")
        return {'log_file': 'logs/password_checker.log'}

def check_password_strength(password, min_length=8):
    """Evaluate password strength and provide feedback."""
    score = 0
    feedback = []
    
    try:
        if not isinstance(password, str):
            raise ValueError("Password must be a string")
        
        if len(password) >= 12:
            score += 2
            feedback.append("Good length (>=12)")
        elif len(password) >= min_length:
            score += 1
            feedback.append("Minimum length met")
        else:
            feedback.append("Too short")
            
        if re.search(r"[A-Z]", password):
            score += 1
            feedback.append("Has uppercase")
        if re.search(r"[a-z]", password):
            score += 1
            feedback.append("Has lowercase")
        if re.search(r"[0-9]", password):
            score += 1
            feedback.append("Has numbers")
        if re.search(r"[!@#$%^&*]", password):
            score += 1
            feedback.append("Has special characters")
            
        return score, feedback
    
    except Exception as e:
        logging.error(f"Error checking password: {e}")
        return 0, [f"Error: {e}"]

def main():
    """Parse arguments and run password strength check."""
    parser = argparse.ArgumentParser(
        description="Evaluate password strength",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "-p", "--password",
        help="Password to check",
        required=True
    )
    parser.add_argument(
        "-l", "--min-length",
        type=int,
        default=8,
        help="Minimum acceptable password length"
    )
    parser.add_argument(
        "-c", "--config",
        default="config.ini",
        help="Path to configuration file"
    )
    
    args = parser.parse_args()
    
    # Setup
    config = load_config(args.config)
    setup_logging(config.get('log_file', 'logs/password_checker.log'))
    
    # Execute
    logging.info(f"Checking password strength (length: {len(args.password)})")
    score, feedback = check_password_strength(args.password, args.min_length)
    
    # Results
    print(f"Password Score: {score}/6")
    for msg in feedback:
        print(f"- {msg}")
    logging.info(f"Password scored {score}/6")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Program terminated by user")
        sys.exit(0)
    except Exception as e:
        logging.critical(f"Unexpected error: {e}")
        sys.exit(1)
