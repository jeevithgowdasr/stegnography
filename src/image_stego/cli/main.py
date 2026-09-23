"""Command-line interface (CLI) for Image Encryption and Steganography."""

import argparse
import getpass
import sys
from pathlib import Path

from ..core.pipeline import encrypt_and_hide, extract_and_decrypt
from ..core.models import PayloadType
from ..core.exceptions import StegoError
from ..stego.capacity import format_bytes
from ..utils.metrics import calculate_quality_metrics, generate_difference_map
from ..utils.image_io import load_image, save_image


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="image-stego",
        description="Secure Image Encryption & Steganography CLI (AES-256-GCM + LSB)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available subcommands")

    # Subcommand: hide
    hide_parser = subparsers.add_parser("hide", help="Encrypt and hide secret data inside an image")
    hide_parser.add_argument("-c", "--cover", required=True, help="Path to cover image (PNG or BMP)")
    hide_parser.add_argument("-p", "--password", help="Secret password (prompts if omitted)")
    group = hide_parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-m", "--message", help="Secret text message to embed")
    group.add_argument("-f", "--file", help="Path to secret file to embed")
    hide_parser.add_argument("-o", "--output", help="Output path for stego image (PNG/BMP)")

    # Subcommand: reveal
    reveal_parser = subparsers.add_parser("reveal", help="Extract and decrypt hidden data from an image")
    reveal_parser.add_argument("-s", "--stego", required=True, help="Path to stego image (PNG or BMP)")
    reveal_parser.add_argument("-p", "--password", help="Secret password (prompts if omitted)")
    reveal_parser.add_argument("-o", "--output-dir", help="Directory to save extracted secret files")

    # Subcommand: metrics
    metrics_parser = subparsers.add_parser("metrics", help="Calculate image quality metrics (PSNR, MSE)")
    metrics_parser.add_argument("-orig", "--original", required=True, help="Path to original image")
    metrics_parser.add_argument("-stego", "--stego", required=True, help="Path to stego image")
    metrics_parser.add_argument("-diff", "--diff-map", help="Optional path to save difference heatmap")

    return parser


def main(args=None):
    parser = build_parser()
    parsed_args = parser.parse_args(args)

    try:
        if parsed_args.command == "hide":
            password = parsed_args.password or getpass.getpass("Enter encryption password: ")
            if not password:
                print("Error: Password cannot be empty.", file=sys.stderr)
                sys.exit(1)

            print(f"[*] Processing cover image: {parsed_args.cover}")
            res = encrypt_and_hide(
                cover_image_path=parsed_args.cover,
                password=password,
                secret_text=parsed_args.message,
                secret_file_path=parsed_args.file,
                output_image_path=parsed_args.output,
            )
            print("[+] Success! Payload encrypted and embedded.")
            print(f"    - Output Image: {res.output_path}")
            print(f"    - Payload Size: {format_bytes(res.payload_bytes)}")
            print(f"    - Image Capacity: {format_bytes(res.capacity_bytes)}")
            print(f"    - Capacity Utilization: {res.capacity_used_pct}%")

        elif parsed_args.command == "reveal":
            password = parsed_args.password or getpass.getpass("Enter decryption password: ")
            if not password:
                print("Error: Password cannot be empty.", file=sys.stderr)
                sys.exit(1)

            print(f"[*] Reading stego image: {parsed_args.stego}")
            res = extract_and_decrypt(
                stego_image_path=parsed_args.stego,
                password=password,
                output_directory=parsed_args.output_dir or ".",
            )

            if res.payload_type == PayloadType.TEXT:
                print("\n=== DECRYPTED SECRET MESSAGE ===")
                print(res.text_content)
                print("================================\n")
            else:
                print("[+] Successfully extracted secret file!")
                print(f"    - Filename: {res.filename}")
                if res.output_file_path:
                    print(f"    - Saved To: {res.output_file_path}")
                else:
                    print(f"    - Size: {format_bytes(len(res.binary_content or b''))}")

        elif parsed_args.command == "metrics":
            print(f"[*] Comparing '{parsed_args.original}' and '{parsed_args.stego}'...")
            metrics = calculate_quality_metrics(parsed_args.original, parsed_args.stego)
            print("\n=== IMAGE QUALITY METRICS ===")
            print(f"  - Peak Signal-to-Noise Ratio (PSNR): {metrics.psnr_db} dB")
            print(f"  - Mean Squared Error (MSE):          {metrics.mse}")
            print(f"  - Max Pixel Difference:              {metrics.max_pixel_diff} / 255")
            print(f"  - Total Modified Pixels:             {metrics.total_pixels_modified:,} / {metrics.total_pixels:,}")
            print(f"  - Percentage Modified:               {metrics.modified_percentage}%")
            print("=============================\n")

            if parsed_args.diff_map:
                orig_arr, _ = load_image(parsed_args.original)
                stego_arr, _ = load_image(parsed_args.stego)
                diff_arr = generate_difference_map(orig_arr, stego_arr)
                save_image(diff_arr, parsed_args.diff_map)
                print(f"[+] Difference heatmap saved to: {parsed_args.diff_map}")

    except StegoError as e:
        print(f"\n[!] Steganography Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Unexpected Error: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
