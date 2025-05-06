#!/usr/bin/env python3
import os
import subprocess
import argparse


def main():
    parser = argparse.ArgumentParser(
        description="Mutate payloads using sgn.exe"
    )
    parser.add_argument(
        '-i', '--input_dir', required=True,
        help="Input directory containing payloads"
    )
    parser.add_argument(
        '-o', '--output_dir', required=True,
        help="Directory to output mutated binaries"
    )
    parser.add_argument(
        '-e', '--exe_path',
        default=r"sgn.exe",
        help="Path to sgn.exe"
    )
    parser.add_argument(
        '-a', '--arch', type=int, choices=[32, 64], default=64,
        help="Binary architecture (32 or 64)"
    )
    parser.add_argument(
        '-c', '--enc', type=int, default=1,
        help="Number of times to encode the binary"
    )
    parser.add_argument(
        '-m', '--max_bytes', type=int, default=50,
        help="Maximum bytes for decoder obfuscation"
    )
    parser.add_argument(
        '--badchars', default="",
        help=r"Bad characters in hex format, e.g. \x00\x0A"
    )
    parser.add_argument(
        '--plain', action='store_true',
        help="Do not encode the decoder stub"
    )
    parser.add_argument(
        '--ascii', action='store_true',
        help="Generate full ASCII printable payload"
    )
    parser.add_argument(
        '--safe', action='store_true',
        help="Preserve all register values (no clobber)"
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help="Verbose mode"
    )

    args = parser.parse_args()

    # Ensure output directory exists
    os.makedirs(args.output_dir, exist_ok=True)

    # Iterate through all files in the input directory
    for filename in os.listdir(args.input_dir):
        input_path = os.path.join(args.input_dir, filename)
        if not os.path.isfile(input_path):
            continue

        # Create output filename
        name, ext = os.path.splitext(filename)
        output_filename = f"{name}_sgn{ext}"
        output_path = os.path.join(args.output_dir, output_filename)

        # Build the sgn.exe command
        cmd = [
            args.exe_path,
            '-i', input_path,
            '-o', output_path,
            '-a', str(args.arch),
            '-c', str(args.enc),
            '-M', str(args.max_bytes),
        ]
        if args.badchars:
            cmd.extend(['--badchars', args.badchars])
        if args.plain:
            cmd.append('--plain')
        if args.ascii:
            cmd.append('--ascii')
        if args.safe:
            cmd.append('-S')
        if args.verbose:
            cmd.append('-v')

        # Execute the command
        print(f"Running: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)


if __name__ == "__main__":
    main()
