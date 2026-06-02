"""
GUN-112 Command Line Interface

Usage:
    gun112 help                          Show all available commands
    gun112 encrypt <file>                Encrypt a PDF with a password
    gun112 encrypt <file> --recipient <token>   Encrypt for a specific recipient
    gun112 decrypt <file>                Decrypt a PDF (auto-detects password vs identity mode)
    gun112 generate-identity             Generate your device's Identity Token
    gun112 show-identity                 Display your Identity Token
    gun112 reset-identity                Delete your identity (WARNING: irreversible)
"""
import argparse
import sys
import json
import getpass
from pathlib import Path

from gun112 import PDFEncryptionHandler
from gun112.identity import IdentityManager


# ── Styling helpers ──────────────────────────────────────────────────────────

def _banner():
    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║          GUN-112  PDF Encryption Protocol               ║")
    print("║     Hardware-Bound · Identity-Locked · AES-256-GCM      ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()


def _success(msg):
    print(f"  ✓ {msg}")


def _error(msg):
    print(f"  ✗ {msg}", file=sys.stderr)


def _info(msg):
    print(f"  ℹ {msg}")


# ── Command implementations ─────────────────────────────────────────────────

def help_command(args):
    """Show detailed help for all GUN-112 commands."""
    _banner()
    print("COMMANDS")
    print("────────────────────────────────────────────────────────────")
    print()
    print("  gun112 help")
    print("      Show this help message with all available commands.")
    print()
    print("  gun112 encrypt <file> [-o OUTPUT]")
    print("      Encrypt a PDF file using a password.")
    print("      You will be securely prompted to enter and confirm")
    print("      your password (it will not appear on screen).")
    print()
    print("  gun112 encrypt <file> --recipient <IDENTITY_TOKEN> [-o OUTPUT]")
    print("      Encrypt a PDF for a specific person using their")
    print("      public Identity Token. No password is needed.")
    print("      Only the recipient's physical device can decrypt it.")
    print()
    print("  gun112 decrypt <file> [-o OUTPUT]")
    print("      Decrypt a GUN-112 encrypted file. The tool will")
    print("      auto-detect whether the file is password-locked or")
    print("      identity-locked and handle it accordingly.")
    print()
    print("  gun112 generate-identity")
    print("      Generate your device's unique Identity Token.")
    print("      A RSA-4096 keypair is created. The private key is")
    print("      stored securely on this device and never leaves it.")
    print("      The public Identity Token is displayed for sharing.")
    print()
    print("  gun112 show-identity")
    print("      Display your existing public Identity Token and its")
    print("      fingerprint so you can share it with others.")
    print()
    print("  gun112 reset-identity")
    print("      Delete your identity from this device.")
    print("      WARNING: Any files encrypted for this identity will")
    print("      become permanently unrecoverable!")
    print()
    print("OPTIONS")
    print("────────────────────────────────────────────────────────────")
    print("  -o, --output PATH     Custom output file path")
    print("  --recipient TOKEN     Recipient's public Identity Token")
    print()
    print("EXAMPLES")
    print("────────────────────────────────────────────────────────────")
    print("  # Password-based encryption")
    print("  gun112 encrypt report.pdf")
    print("  gun112 decrypt report.pdf.encrypted")
    print()
    print("  # Identity-based encryption (no password needed)")
    print("  gun112 generate-identity")
    print("  gun112 encrypt report.pdf --recipient <Bob's_Token>")
    print("  # Bob runs on his machine:")
    print("  gun112 decrypt report.pdf.encrypted")
    print()


def encrypt_command(args):
    """Encrypt a PDF file."""
    try:
        input_path = Path(args.input)
        if not input_path.exists():
            _error(f"File not found: {args.input}")
            sys.exit(1)

        with open(input_path, "rb") as f:
            data = f.read()

        handler = PDFEncryptionHandler()
        output_path = args.output if args.output else str(input_path) + ".encrypted"

        if args.recipient:
            # ── Identity-locked encryption ──
            _info("Encrypting for recipient's Identity Token...")
            encrypted_data = handler.encrypt_pdf_for_recipient(data, args.recipient)
            with open(output_path, "wb") as f:
                f.write(encrypted_data)
            _success(f"Identity-locked file saved to {output_path}")
            _info("Only the recipient's physical device can decrypt this file.")
        else:
            # ── Password-locked encryption ──
            password = getpass.getpass("  Enter password for encryption: ")
            confirm = getpass.getpass("  Confirm password: ")
            if password != confirm:
                _error("Passwords do not match.")
                sys.exit(1)

            encrypted_data = handler.encrypt_pdf(data, password)
            with open(output_path, "wb") as f:
                f.write(encrypted_data)
            _success(f"Password-locked file saved to {output_path}")

    except Exception as e:
        _error(f"Encryption failed: {e}")
        sys.exit(1)


def decrypt_command(args):
    """Decrypt a GUN-112 encrypted file (auto-detects lock mode)."""
    try:
        input_path = Path(args.input)
        if not input_path.exists():
            _error(f"File not found: {args.input}")
            sys.exit(1)

        with open(input_path, "rb") as f:
            data = f.read()

        # Auto-detect lock mode from the container
        try:
            container = json.loads(data.decode("utf-8"))
            lock_mode = container.get("lock_mode", "password")
        except Exception:
            lock_mode = "password"

        handler = PDFEncryptionHandler()
        output_path = args.output if args.output else str(input_path).replace(
            ".encrypted", ".decrypted.pdf"
        )

        if lock_mode == "identity":
            # ── Identity-locked decryption ──
            _info("Identity-locked file detected. Using device private key...")
            decrypted_data, metadata = handler.decrypt_pdf_identity(data)
            with open(output_path, "wb") as f:
                f.write(decrypted_data)
            _success(f"Decrypted file saved to {output_path}")
            if metadata:
                _info(f"Metadata recovered: {metadata}")
        else:
            # ── Password-locked decryption ──
            password = getpass.getpass("  Enter password for decryption: ")
            decrypted_data, metadata = handler.decrypt_pdf(data, password)
            with open(output_path, "wb") as f:
                f.write(decrypted_data)
            _success(f"Decrypted file saved to {output_path}")
            if metadata:
                _info(f"Metadata recovered: {metadata}")

    except ValueError as e:
        _error(f"Decryption failed: {e}")
        sys.exit(1)
    except Exception as e:
        _error(f"An error occurred: {e}")
        sys.exit(1)


def generate_identity_command(args):
    """Generate a new device Identity Token."""
    _banner()
    try:
        manager = IdentityManager()

        passphrase = None
        response = input("  Protect private key with a passphrase? (y/N): ").strip().lower()
        if response == "y":
            passphrase = getpass.getpass("  Enter passphrase: ")
            confirm = getpass.getpass("  Confirm passphrase: ")
            if passphrase != confirm:
                _error("Passphrases do not match.")
                sys.exit(1)

        _info("Generating RSA-4096 keypair... (this may take a moment)")
        token = manager.generate_identity(passphrase)
        fingerprint = manager.get_identity_fingerprint(token)

        _success("Identity generated successfully!")
        print()
        print("  Your Identity Token (share this with others):")
        print(f"  {token[:80]}...")
        print()
        print(f"  Fingerprint: {fingerprint}")
        print()
        _info("Your private key is stored securely on this device.")
        _info("Run 'gun112 show-identity' to see the full token anytime.")

    except FileExistsError as e:
        _error(str(e))
        sys.exit(1)
    except Exception as e:
        _error(f"Identity generation failed: {e}")
        sys.exit(1)


def show_identity_command(args):
    """Display the current device Identity Token."""
    try:
        manager = IdentityManager()
        token = manager.get_identity_token()
        fingerprint = manager.get_identity_fingerprint(token)

        _banner()
        print("  Your Identity Token:")
        print(f"  {token}")
        print()
        print(f"  Fingerprint: {fingerprint}")
        print()
        _info("Share the token above with anyone who wants to send you encrypted files.")

    except FileNotFoundError as e:
        _error(str(e))
        sys.exit(1)


def reset_identity_command(args):
    """Delete the device identity (irreversible)."""
    _banner()
    print("  ⚠  WARNING: This will permanently delete your identity.")
    print("     Any files encrypted for this identity will become")
    print("     PERMANENTLY UNRECOVERABLE.")
    print()
    confirm = input("  Type 'DELETE' to confirm: ").strip()
    if confirm != "DELETE":
        _info("Reset cancelled.")
        return

    manager = IdentityManager()
    manager.reset_identity()
    _success("Identity has been deleted from this device.")


# ── CLI entry point ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="gun112",
        description="GUN-112 PDF Encryption Protocol — Hardware-Bound · Identity-Locked · AES-256-GCM",
        add_help=False  # We provide our own 'help' subcommand
    )
    subparsers = parser.add_subparsers(dest="command")

    # gun112 help
    help_parser = subparsers.add_parser("help", help="Show all available commands and usage")
    help_parser.set_defaults(func=help_command)

    # gun112 encrypt
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a PDF file")
    encrypt_parser.add_argument("input", help="Path to the PDF file")
    encrypt_parser.add_argument("-o", "--output", help="Custom output file path")
    encrypt_parser.add_argument(
        "--recipient",
        help="Recipient's public Identity Token (for identity-locked encryption)",
        default=None
    )
    encrypt_parser.set_defaults(func=encrypt_command)

    # gun112 decrypt
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a GUN-112 encrypted file")
    decrypt_parser.add_argument("input", help="Path to the encrypted file")
    decrypt_parser.add_argument("-o", "--output", help="Custom output file path")
    decrypt_parser.set_defaults(func=decrypt_command)

    # gun112 generate-identity
    gen_parser = subparsers.add_parser("generate-identity", help="Generate your device Identity Token")
    gen_parser.set_defaults(func=generate_identity_command)

    # gun112 show-identity
    show_parser = subparsers.add_parser("show-identity", help="Display your Identity Token")
    show_parser.set_defaults(func=show_identity_command)

    # gun112 reset-identity
    reset_parser = subparsers.add_parser("reset-identity", help="Delete your identity (irreversible)")
    reset_parser.set_defaults(func=reset_identity_command)

    args = parser.parse_args()

    if args.command is None:
        # No command given — show help by default
        help_command(args)
    else:
        args.func(args)


if __name__ == "__main__":
    main()
