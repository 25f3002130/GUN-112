import argparse
import sys
import getpass
from pathlib import Path
from gun112 import PDFEncryptionHandler

def encrypt_command(args):
    try:
        input_path = Path(args.input)
        if not input_path.exists():
            print(f"Error: File {args.input} does not exist.")
            sys.exit(1)
            
        with open(input_path, 'rb') as f:
            data = f.read()
            
        password = getpass.getpass("Enter password for encryption: ")
        confirm_password = getpass.getpass("Confirm password: ")
        
        if password != confirm_password:
            print("Error: Passwords do not match.")
            sys.exit(1)
            
        handler = PDFEncryptionHandler()
        encrypted_data = handler.encrypt_pdf(data, password)
        
        output_path = args.output if args.output else str(input_path) + ".encrypted"
        with open(output_path, 'wb') as f:
            f.write(encrypted_data)
            
        print(f"Successfully encrypted {args.input} to {output_path}")
    except Exception as e:
        print(f"Encryption failed: {e}")
        sys.exit(1)

def decrypt_command(args):
    try:
        input_path = Path(args.input)
        if not input_path.exists():
            print(f"Error: File {args.input} does not exist.")
            sys.exit(1)
            
        with open(input_path, 'rb') as f:
            data = f.read()
            
        password = getpass.getpass("Enter password for decryption: ")
        
        handler = PDFEncryptionHandler()
        decrypted_data, metadata = handler.decrypt_pdf(data, password)
        
        output_path = args.output if args.output else str(input_path).replace(".encrypted", ".decrypted.pdf")
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
            
        print(f"Successfully decrypted {args.input} to {output_path}")
        if metadata:
            print(f"Metadata recovered: {metadata}")
    except ValueError as e:
        print(f"Decryption failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="GUN-112 PDF Encryption Protocol CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a PDF file")
    encrypt_parser.add_argument("input", help="Path to the PDF file")
    encrypt_parser.add_argument("-o", "--output", help="Path for the encrypted output file")
    encrypt_parser.set_defaults(func=encrypt_command)
    
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a GUN-112 encrypted file")
    decrypt_parser.add_argument("input", help="Path to the encrypted file")
    decrypt_parser.add_argument("-o", "--output", help="Path for the decrypted output file")
    decrypt_parser.set_defaults(func=decrypt_command)
    
    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
